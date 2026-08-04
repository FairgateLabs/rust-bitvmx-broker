use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::sleep,
    time::Duration,
};

#[cfg(feature = "storagebackend")]
use bitvmx_broker::storage;
use bitvmx_settings::settings;
#[cfg(feature = "storagebackend")]
use storage::db::DbStorage;
#[cfg(feature = "storagebackend")]
use storage_backend::{storage::Storage, storage_config::StorageConfig};

use tracing_subscriber::{fmt::format::FmtSpan, prelude::*, EnvFilter};

use bitvmx_broker::{
    identification::{allow_list::AllowList, routing::RoutingTable},
    rpc::{config::BrokerSettings, server::BrokerServer, tls_helper::Cert, BrokerConfig},
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
    let privk = settings::decrypt_or_read_file("../rust-bitvmx-client/config/keys/services.key")
        .expect("Failed to read private key file");
    let cert = Cert::new_with_privk(privk.as_str()).unwrap();
    let allow_list = AllowList::new();
    allow_list.lock().unwrap().allow_all();
    let routing = RoutingTable::new();
    routing.lock().unwrap().allow_all();
    let config = BrokerSettings::new("config/broker_settings.yaml").unwrap();
    let config = BrokerConfig::new(
        flags.port,
        None,
        cert.get_pubk_hash().unwrap(),
        Some(config),
    );

    #[cfg(not(feature = "storagebackend"))]
    let storage = Arc::new(Mutex::new(
        bitvmx_broker::storage::memory::MemStorage::new(),
    ));
    #[cfg(feature = "storagebackend")]
    let storage = {
        let storage_path = "storage.db";
        let config = StorageConfig::new(storage_path.to_string(), None);
        let broker_backend = Storage::new(&config).unwrap();
        let broker_backend = Arc::new(Mutex::new(broker_backend));
        Arc::new(Mutex::new(DbStorage::new(broker_backend)))
    };

    let mut server =
        BrokerServer::new(&config, storage.clone(), cert, allow_list.clone(), routing).unwrap();

    wait_ctrl();
    server.close();
    sleep(Duration::from_secs(1));

    #[cfg(not(feature = "storagebackend"))]
    info!("Storage data: {:?}", storage.lock().unwrap());
}
