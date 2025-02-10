use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[cfg(not(feature = "storagebackend"))]
use bitvmx_broker::broker_memstorage::MemStorage;
use bitvmx_broker::{
    channel::channel::DualChannel,
    rpc::{client::Client, sync_server::BrokerSync, BrokerConfig},
};
#[cfg(feature = "storagebackend")]
use storage_backend::storage::Storage;

fn prepare(port: u16) -> (BrokerSync, BrokerConfig) {
    #[cfg(not(feature = "storagebackend"))]
    let storage = Arc::new(Mutex::new(MemStorage::new()));
    #[cfg(feature = "storagebackend")]
    let backend = Storage::new_with_path(&PathBuf::from("storage.db")).unwrap();
    #[cfg(feature = "storagebackend")]
    let storage = Arc::new(Mutex::new(
        bitvmx_broker::broker_storage::BrokerStorage::new(Arc::new(Mutex::new(backend))),
    ));
    let config = BrokerConfig::new(port, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server = BrokerSync::new(&config, storage.clone());
    (server, config)
}

fn cleanup_storage() {
    let _ = fs::remove_dir_all(&PathBuf::from("storage.db"));
}

#[test]
fn test_channel() {
    cleanup_storage();
    let (mut server, config) = prepare(10000);
    let user_1 = DualChannel::new(&config, 1);
    let user_2 = DualChannel::new(&config, 2);

    user_1.send(2, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();
    assert_eq!(msg, "Hello!");
    server.close();
    cleanup_storage();
}

#[test]
fn test_ack() {
    cleanup_storage();
    let (mut server, config) = prepare(10001);

    let client = Client::new(&config);
    client.send_msg(1, 2, "Hello!".to_string()).unwrap();

    let msg = client.get_msg(2).unwrap().unwrap();
    assert_eq!(msg.msg, "Hello!");
    let msg_dup = client.get_msg(2).unwrap().unwrap();
    assert_eq!(msg.uid, msg_dup.uid);
    assert!(client.ack(2, msg.uid).unwrap());
    println!("{:?}", client.get_msg(2).unwrap());
    assert!(client.get_msg(2).unwrap().is_none());
    server.close();
    cleanup_storage();
}
