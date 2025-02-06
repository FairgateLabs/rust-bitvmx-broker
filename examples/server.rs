use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::sleep,
    time::Duration,
};
use tracing_subscriber::{fmt::format::FmtSpan, prelude::*, EnvFilter};

use bitvmx_broker::rpc::{server::StorageApi, sync_server::BrokerSync, BrokerConfig};
use clap::Parser;
use tracing::info;

#[derive(Parser)]
struct Flags {
    /// Sets the port number to listen on.
    #[clap(long)]
    port: u16,
}

#[derive(Clone)]
pub struct MemStorage {
    data: HashMap<u32, VecDeque<String>>,
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
impl MemStorage {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl StorageApi for MemStorage {
    fn pop(&mut self, id: u32) -> Option<String> {
        self.data.get_mut(&id)?.pop_front()
    }

    fn insert(&mut self, id: u32, msg: String) {
        self.data.entry(id).or_default().push_back(msg);
    }
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
    let config = BrokerConfig {
        port: flags.port,
        ip: None,
    };

    let storage = Arc::new(Mutex::new(MemStorage::new()));

    let mut server = BrokerSync::new(config, storage.clone());

    storage
        .lock()
        .unwrap()
        .insert(1, "Hello everyone".to_string());

    wait_ctrl();
    server.close();
    sleep(Duration::from_secs(1));

    info!("Storage data: {:?}", storage.lock().unwrap().data);
}
