use anyhow::{anyhow, Result};
use clap::Parser;
use itertools::Itertools;
use log::{debug, error, info, LevelFilter};
use tokio::net::UdpSocket;

const LOCAL_ADDRESS: &str = "0.0.0.0";
const DEFAULT_LOCAL_PORT: u32 = 8043;
const DEFAULT_REMOTE_ADDRESS: &str = "8.8.8.8";
const REMOTE_ADDRESS_PORT: u32 = 53;
const HEADER: &str = "AAAA01000001000000000000";

// TODO: local cache supporting TTL

/// Simple DNS lookup.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Domain to resolve
    address: String,

    /// DNS server to use (defaults to Google's 8.8.8.8)
    #[arg(short, long)]
    server: Option<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Local port to bind to (defaults to 8043)
    #[arg(short, long)]
    port: Option<u32>,
}

/// Build the DNS query question by converting the address to HEX
/// and adding the other pieces.
fn build_question(address: &str) -> String {
    let mut buffer = String::new();
    for part in address.split('.') {
        buffer.push_str(&format!("{:0>2X}", part.len()));
        buffer.push_str(&hex::encode_upper(part));
    }
    buffer.push_str("0000010001");
    buffer.to_owned()
}

/// Submit the query to the DNS server over UDP.
async fn submit_query(query: &[u8], server: &str, port: u32) -> Result<String> {
    let socket = UdpSocket::bind(format!("{}:{}", LOCAL_ADDRESS, port)).await?;
    socket.connect(server).await?;

    let written = socket.send_to(query, server).await?;
    debug!("Wrote {written} bytes");

    let mut buffer = [0u8; 4096];
    let read = socket.recv(&mut buffer).await?;
    if read == 0 {
        return Err(anyhow!("Did not read back any data"));
    }

    debug!("Read {read} bytes");
    Ok(hex::encode_upper(&buffer[..read]))
}

/// Parse the response from the DNS server into an IP address.
fn parse_response(response: &str) -> String {
    let header: String = response.chars().take(24).collect();
    debug!("Response header: {header}");

    let body: String = response.chars().skip(24).collect();
    debug!("Response body: {body}");
    body[body.len() - 8..]
        .chars()
        .chunks(2)
        .into_iter()
        .map(|mut chunk| chunk.join(""))
        .flat_map(|str| hex::decode(str).expect("Received invalid hex code"))
        .map(|oct| oct.to_string())
        .join(".")
}

/// Resolve a domain to an IP.
pub async fn resolve_address(address: &str, server: &str, port: u32) -> Result<String> {
    let query = hex::decode(format!("{}{}", HEADER, build_question(address)))?;
    let response = submit_query(&query, server, port).await?;
    let ip = parse_response(&response);
    Ok(ip)
}

/// Configure the logger.
///
/// Info logs are just the message; other logs include the log level.
fn setup_logger(debug: bool) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            if record.level() == LevelFilter::Info {
                out.finish(format_args!("{}", message))
            } else {
                out.finish(format_args!("[{}] {}", record.level(), message))
            }
        })
        .level(if debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        })
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    setup_logger(args.debug)?;

    let remote = format!(
        "{}:{}",
        args.server
            .unwrap_or_else(|| DEFAULT_REMOTE_ADDRESS.to_string()),
        REMOTE_ADDRESS_PORT
    );

    match resolve_address(
        &args.address,
        &remote,
        args.port.unwrap_or(DEFAULT_LOCAL_PORT),
    )
    .await
    {
        Ok(ip) => info!("{ip}"),
        Err(e) => error!("Processing error: {e}"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_question, parse_response};

    #[test]
    fn test_address_to_hex() {
        assert_eq!(
            build_question("example.com"),
            "076578616D706C6503636F6D0000010001"
        );
    }

    #[test]
    fn test_parse_response() {
        assert_eq!(
            parse_response("076578616D706C6503636F6D0000010001C00C0001000100004CDB00045DB8D822"),
            "93.184.216.34"
        );
    }
}
