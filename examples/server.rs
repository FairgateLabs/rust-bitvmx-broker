use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::sleep,
    time::Duration,
};
use tracing_subscriber::{fmt::format::FmtSpan, prelude::*, EnvFilter};

use bitvmx_broker::rpc::{sync_server::BrokerSync, BrokerConfig};
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
    let certs = BrokerConfig::get_local_cert_files("server");
    let config = BrokerConfig {
        port: flags.port,
        ip: None,
        cert_files: certs,
    };

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

    let mut server = BrokerSync::new(&config, storage.clone());

    wait_ctrl();
    server.close();
    sleep(Duration::from_secs(1));

    #[cfg(not(feature = "storagebackend"))]
    info!("Storage data: {:?}", storage.lock().unwrap());
}
