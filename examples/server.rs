use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::sleep,
    time::Duration,
};

#[cfg(feature = "storagebackend")]
use broker_storage::BrokerStorage;
#[cfg(feature = "storagebackend")]
use storage_backend::{storage::Storage, storage_config::StorageConfig};

use tracing_subscriber::{fmt::format::FmtSpan, prelude::*, EnvFilter};

use bitvmx_broker::{
    identification::{allow_list::AllowList, routing::RoutingTable},
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
    let privk = fs::read_to_string("certs/services.key").expect("Failed to read private key file");
    let cert = Cert::new_with_privk(&privk).unwrap();
    let allow_list =
        AllowList::from_certs(vec![cert.clone()], vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).unwrap();
    let routing = RoutingTable::new();
    routing.lock().unwrap().allow_all();
    let config = BrokerConfig::new(flags.port, None, cert.get_pubk_hash().unwrap(), None).unwrap();

    #[cfg(not(feature = "storagebackend"))]
    let storage = Arc::new(Mutex::new(
        bitvmx_broker::broker_memstorage::MemStorage::new(),
    ));
    #[cfg(feature = "storagebackend")]
    let storage = {
        let storage_path = "storage.db";
        let config = StorageConfig::new(storage_path.to_string(), None);
        let broker_backend = Storage::new(&config).unwrap();
        let broker_backend = Arc::new(Mutex::new(broker_backend));
        Arc::new(Mutex::new(BrokerStorage::new(broker_backend)))
    };

    let mut server = BrokerSync::new(&config, storage.clone(), cert, allow_list.clone(), routing);

    wait_ctrl();
    server.close();
    sleep(Duration::from_secs(1));

    #[cfg(not(feature = "storagebackend"))]
    info!("Storage data: {:?}", storage.lock().unwrap());
}
