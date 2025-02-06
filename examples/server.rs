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

use bitvmx_broker::rpc::{sync_server::BrokerSync, BrokerConfig, Message, StorageApi};
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

#[derive(Clone)]
pub struct MemStorage {
    uid: u64,
    data: HashMap<u32, VecDeque<Message>>,
}

impl MemStorage {
    pub fn new() -> Self {
        Self {
            uid: 0,
            data: HashMap::new(),
        }
    }
}

impl StorageApi for MemStorage {
    fn get(&mut self, dest: u32) -> Option<Message> {
        self.data.get_mut(&dest)?.front().cloned()
    }

    fn remove(&mut self, dest: u32, uid: u64) -> bool {
        let data = self.data.get_mut(&dest);
        if let Some(data) = data {
            if data.front().map(|m| m.uid) == Some(uid) {
                data.pop_front();
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    fn insert(&mut self, from: u32, dest: u32, msg: String) {
        self.uid += 1;
        let msg = Message {
            uid: self.uid,
            from,
            msg,
        };
        self.data.entry(dest).or_default().push_back(msg);
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

    wait_ctrl();
    server.close();
    sleep(Duration::from_secs(1));

    info!("Storage data: {:?}", storage.lock().unwrap().data);
}
