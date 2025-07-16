use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::sleep,
    time::Duration,
};
use tracing_subscriber::{fmt::format::FmtSpan, prelude::*, EnvFilter};

use bitvmx_broker::{
    allow_list::AllowList,
    rpc::{sync_server::BrokerSync, tls_helper::Cert, BrokerConfig},
};
use clap::Parser;
use tracing::info;

#[derive(Parser)]
struct Flags {
    /// Sets the port number to listen on.
    #[clap(long)]
    port: u16,
}

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
fn wait_ctrl() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    info!("Press Ctrl+C to stop...");

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(200));
    }
}

fn main() {
    init_tracing().unwrap();
    let flags = Flags::parse();
    let cert = Cert::new().unwrap();
    let allow_list =
        AllowList::from_certs(vec![cert.clone()], vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).unwrap();
    let config = BrokerConfig::new(flags.port, None, cert.get_pubk_hash().unwrap()).unwrap();

    #[cfg(not(feature = "storagebackend"))]
    let storage = Arc::new(Mutex::new(
        bitvmx_broker::broker_memstorage::MemStorage::new(),
    ));
    #[cfg(feature = "storagebackend")]
    let backend =
        storage_backend::storage::Storage::new_with_path(&std::path::PathBuf::from("storage.db"))
            .unwrap();
    #[cfg(feature = "storagebackend")]
    let storage = Arc::new(Mutex::new(
        bitvmx_broker::broker_storage::BrokerStorage::new(Arc::new(Mutex::new(backend))),
    ));

    let mut server = BrokerSync::new(&config, storage.clone(), cert, allow_list.clone());

    wait_ctrl();
    server.close();
    sleep(Duration::from_secs(1));

    #[cfg(not(feature = "storagebackend"))]
    info!("Storage data: {:?}", storage.lock().unwrap());
}
