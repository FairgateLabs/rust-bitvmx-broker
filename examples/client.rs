use bitvmx_broker::rpc::{client::Client, BrokerConfig};
use clap::Parser;
use std::{net::IpAddr, thread::sleep, time::Duration};
use tracing_subscriber::{fmt::format::FmtSpan, prelude::*, EnvFilter};

pub fn init_tracing() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .parse("info,tarpc=off") // Include everything at "info" except `libp2p`
        .expect("Invalid filter");

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
        .try_init()?;

    Ok(())
}

#[derive(Parser)]
struct Flags {
    /// Sets the server address to connect to.
    #[clap(long)]
    ip_addr: IpAddr,

    /// Sets the port number to connect to.
    #[clap(long)]
    port: u16,

    /// Sets the id to send the message to.
    #[clap(long)]
    id: u32,

    /// Message to send.
    #[clap(long)]
    msg: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let flags = Flags::parse();
    init_tracing()?;

    let client = Client::new(BrokerConfig::new(flags.port, Some(flags.ip_addr)));

    match &flags.msg {
        Some(msg) => {
            let _ret = client.send_msg(flags.id, msg.clone());
        }
        None => {
            let msgs = client.get_msg(flags.id);
            for msg in msgs {
                println!("{}", msg);
            }
        }
    }

    let _ = sleep(Duration::from_micros(100));

    Ok(())
}
