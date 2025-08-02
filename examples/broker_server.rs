use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

use bitvmx_broker::broker_memstorage::MemStorage;

use bitvmx_broker::{
    rpc::{sync_server::BrokerSync, BrokerConfig},
};

fn main() -> anyhow::Result<()> {
    let storage = Arc::new(Mutex::new(MemStorage::new()));
    let config = BrokerConfig::new(10000, Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    let mut server = BrokerSync::new(&config, storage.clone());

    println!("Starting server on {:#?}:{}", config.ip, config.port);
    // Handle Ctrl+C to gracefully shut down the server
    ctrlc::set_handler(move || {
        println!("server closed");
        server.close();
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    // Keep the main thread alive
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
