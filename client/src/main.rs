use anyhow::Result;
use itertools::Itertools;
use log::{debug, error, info, warn};
use tokio::net::UdpSocket;

const LOCAL_ADDRESS: &str = "0.0.0.0:8080";
const REMOTE_ADDRESS: &str = "8.8.8.8:53";

fn packet() -> Result<Vec<u8>> {
    let header = "AA AA 01 00 00 01 00 00 00 00 00 00";
    let body = "07 65 78 61 6D 70 6C 65 03 63 6F 6D 00 00 01 00 01";
    let encoded = hex::decode(format!("{} {}", header, body).replace(" ", ""))?;
    Ok(encoded)
}

async fn udp() -> Result<()> {
    let socket = UdpSocket::bind(LOCAL_ADDRESS).await?;
    socket.connect(REMOTE_ADDRESS).await?;

    let written = socket.send_to(&packet()?, REMOTE_ADDRESS).await?;
    debug!("Wrote {} bytes", written);

    let mut buffer = [0u8; 4096];
    let read = socket.recv(&mut buffer).await?;
    if read == 0 {
        warn!("No data read");
    } else {
        info!(
            "Returned data: {:?}",
            hex::encode_upper(&buffer[..read])
                .chars()
                .chunks(2)
                .into_iter()
                .map(|s| s.map(|e| e.to_string()).collect::<Vec<String>>().join(""))
                .join(" ")
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    pretty_env_logger::init();

    if let Err(e) = udp().await {
        error!("{}", e);
    }

    Ok(())
}
