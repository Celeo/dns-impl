use anyhow::{anyhow, Result};
use clap::Parser;
use itertools::Itertools;
use log::{debug, error};
use std::env;
use tokio::net::UdpSocket;

const LOCAL_ADDRESS: &str = "0.0.0.0";
const DEFAULT_LOCAL_PORT: u32 = 8043;
const DEFAULT_REMOTE_ADDRESS: &str = "8.8.8.8";
const REMOTE_ADDRESS_PORT: u32 = 53;
const HEADER: &str = "AAAA01000001000000000000";

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
    debug!("Wrote {} bytes", written);

    let mut buffer = [0u8; 4096];
    let read = socket.recv(&mut buffer).await?;
    if read == 0 {
        return Err(anyhow!("Did not read back any data"));
    }

    debug!("Read {} bytes", read);
    Ok(hex::encode_upper(&buffer[..read])
        .chars()
        .chunks(2)
        .into_iter()
        .map(|s| s.map(|e| e.to_string()).collect::<Vec<String>>().join(""))
        .join(" "))
}

/// Parse the response from the DNS server into an IP address.
fn parse_response(response: &str) -> Result<String> {
    // TODO

    unimplemented!()
}

/// Resolve a domain to an IP.
pub async fn resolve_address(address: &str, server: &str, port: u32) -> Result<String> {
    let query = hex::decode(format!("{}{}", HEADER, build_question(address)))?;
    let response = submit_query(&query, server, port).await?;
    let ip = parse_response(&response)?;
    Ok(ip)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.debug {
        env::set_var("RUST_LOG", "debug");
    } else if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init();

    let remote = format!(
        "{}:{}",
        args.server
            .unwrap_or_else(|| DEFAULT_REMOTE_ADDRESS.to_string()),
        REMOTE_ADDRESS_PORT
    );
    let res = resolve_address(
        &args.address,
        &remote,
        args.port.unwrap_or(DEFAULT_LOCAL_PORT),
    )
    .await;
    if let Err(e) = res {
        error!("{}", e);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::build_question;

    #[test]
    fn test_address_to_hex() {
        assert_eq!(
            build_question("example.com"),
            "076578616D706C6503636F6D0000010001"
        );
    }
}
