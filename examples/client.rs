use bitvmx_broker::{
    allow_list::AllowList,
    rpc::{client::Client, tls_helper::Cert, BrokerConfig},
};
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

    /// Sets the id to send the message from.
    #[clap(long)]
    from: Option<u32>,

    /// Sets the id to send the message to.
    #[clap(long)]
    dest: u32,

    /// Message to send.
    #[clap(long)]
    msg: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let flags = Flags::parse();
    init_tracing()?;

    let cert = Cert::new().unwrap();
    let allow_list = AllowList::from_certs(vec![cert.clone()]).unwrap();
    let client =
        Client::new(&BrokerConfig::new(flags.port, Some(flags.ip_addr), cert, allow_list).unwrap())
            .unwrap();

    match &flags.msg {
        Some(msg) => {
            let _ret = client.send_msg(flags.from.unwrap(), flags.dest, msg.clone());
        }
        None => {
            while let Some(msg) = client.get_msg(flags.dest).unwrap_or(None) {
                println!("{:?}", msg);
                client.ack(flags.dest, msg.uid).unwrap();
            }
        }
    }

    let _ = sleep(Duration::from_micros(100));

    Ok(())
}
