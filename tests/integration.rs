use bitvmx_broker::rpc::tls_helper::Cert;
use std::{
    fs::{self},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[cfg(not(feature = "storagebackend"))]
use bitvmx_broker::broker_memstorage::MemStorage;
#[cfg(feature = "storagebackend")]
use bitvmx_broker::broker_storage::BrokerStorage;
use bitvmx_broker::{
    allow_list::AllowList,
    channel::channel::{DualChannel, LocalChannel},
    rpc::{client::Client, errors::BrokerError, sync_server::BrokerSync, BrokerConfig},
};
#[cfg(feature = "storagebackend")]
use storage_backend::storage::Storage;
use tarpc::client::RpcError;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

#[cfg(not(feature = "storagebackend"))]
fn prepare(
    port: u16,
) -> (
    BrokerSync,
    BrokerConfig,
    Arc<Mutex<AllowList>>,
    LocalChannel<MemStorage>,
) {
    let storage = Arc::new(Mutex::new(MemStorage::new()));
    let server_cert = Cert::new("server").unwrap();
    let client_cert = Cert::new("peer1").unwrap();
    let allow_list = AllowList::from_certs(vec![server_cert.clone(), client_cert.clone()]).unwrap();
    let server_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_cert,
        allow_list.clone(),
    );
    let server = BrokerSync::new(&server_config, storage.clone());

    let client_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        client_cert,
        allow_list.clone(),
    );
    let local = LocalChannel::new(1, storage.clone());

    (server, client_config, allow_list, local)
}

#[cfg(feature = "storagebackend")]
fn prepare(
    port: u16,
) -> (
    BrokerSync,
    BrokerConfig,
    Arc<Mutex<AllowList>>,
    LocalChannel<BrokerStorage>,
) {
    let backend = Storage::new_with_path(&PathBuf::from(format!("storage_{}.db", port))).unwrap();
    let storage = Arc::new(Mutex::new(
        bitvmx_broker::broker_storage::BrokerStorage::new(Arc::new(Mutex::new(backend))),
    ));

    let server_cert = Cert::new("server").unwrap();
    let client_cert = Cert::new("peer1").unwrap();
    let allow_list = AllowList::from_certs(vec![server_cert.clone(), client_cert.clone()]).unwrap();

    let server_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_cert,
        allow_list.clone(),
    );
    let server = BrokerSync::new(&server_config, storage.clone());

    let client_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        client_cert,
        allow_list.clone(),
    );

    let local = LocalChannel::new(1, storage.clone());

    (server, config, allow_list, local)
}

fn cleanup_storage(port: u16) {
    let _ = fs::remove_dir_all(&PathBuf::from(format!("storage_{}.db", port)));
}

#[test]
fn test_channel() {
    cleanup_storage(10000);
    let (mut server, config, _, _) = prepare(10000);
    let user_1 = DualChannel::new(&config, 1).unwrap();
    let user_2 = DualChannel::new(&config, 2).unwrap();

    user_1.send(2, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, 1);
    server.close();
    cleanup_storage(10000);
}

#[test]
fn test_ack() {
    cleanup_storage(10001);
    let (mut server, config, _, _) = prepare(10001);

    let client = Client::new(&config).unwrap();
    client.send_msg(1, 2, "Hello!".to_string()).unwrap();

    let msg = client.get_msg(2).unwrap().unwrap();
    assert_eq!(msg.msg, "Hello!");
    let msg_dup = client.get_msg(2).unwrap().unwrap();
    assert_eq!(msg.uid, msg_dup.uid);
    assert!(client.ack(2, msg.uid).unwrap());
    println!("{:?}", client.get_msg(2).unwrap());
    assert!(client.get_msg(2).unwrap().is_none());
    server.close();
    cleanup_storage(10001);
}

#[test]
fn test_reconnect() {
    cleanup_storage(10002);
    let (mut server, config, _, _) = prepare(10002);
    let client = Client::new(&config).unwrap();

    client.send_msg(1, 2, "Hello!".to_string()).unwrap();
    let msg = client.get_msg(2).unwrap().unwrap();
    assert_eq!(msg.msg, "Hello!");
    assert!(client.ack(2, msg.uid).unwrap());
    server.close();

    std::thread::sleep(std::time::Duration::from_secs(2));

    let (mut server, _config, _, _) = prepare(10002);
    std::thread::sleep(std::time::Duration::from_secs(1));

    client.send_msg(1, 2, "World!".to_string()).unwrap();
    let msg = client.get_msg(2).unwrap().unwrap();
    assert_eq!(msg.msg, "World!");
    server.close();
}

#[test]
fn test_stress_channel() {
    init_tracing().unwrap();
    cleanup_storage(10003);
    let (mut server, config, _, _) = prepare(10003);
    let user_1 = DualChannel::new(&config, 1).unwrap();
    let user_2 = DualChannel::new(&config, 2).unwrap();

    for i in 0..1000 {
        println!("Sending: {}", i);
        let send_ok = user_1.send(2, "Hello!".to_string());
        if send_ok.is_err() {
            println!("Error: {:?}", send_ok);
        }
        assert!(send_ok.is_ok());

        let mut ok = false;

        while !ok {
            let try_recv = user_2.recv();
            if try_recv.is_err() {
                println!("Error: {:?}", try_recv);
            }
            assert!(try_recv.is_ok());
            let recv_ok = try_recv.unwrap();
            if recv_ok.is_none() {
                continue;
            }
            assert!(recv_ok.is_some());

            ok = true;
            let msg = recv_ok.unwrap();
            assert_eq!(msg.0, "Hello!");
            assert_eq!(msg.1, 1);
        }
    }
    server.close();
    cleanup_storage(10003);
}

#[test]
fn test_local_channel() {
    cleanup_storage(10010);
    let (mut server, config, _, user_1) = prepare(10010);
    let user_2 = DualChannel::new(&config, 2).unwrap();

    user_1.send(2, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, 1);
    server.close();
    cleanup_storage(10010);
}

#[test]
fn test_dinamic_allow_list() {
    cleanup_storage(10004);
    let (mut server, config, allow_list, _) = prepare(10004);
    let user_1 = DualChannel::new(&config, 1).unwrap();
    let user_2 = DualChannel::new(&config, 2).unwrap();
    let removed;

    {
        removed = allow_list.lock().unwrap().remove_by_value("peer1");
    }

    let err = user_1.send(2, "Hello!".to_string()).unwrap_err();
    let msg = user_2.recv().unwrap_err();
    assert!(matches!(err, BrokerError::RpcError(RpcError::Channel(_))));
    assert!(matches!(msg, BrokerError::RpcError(RpcError::Channel(_))));

    let (key, value) = removed.unwrap();
    {
        allow_list.lock().unwrap().add(key, value);
    }
    user_1.send(2, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();

    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, 1);

    server.close();
    cleanup_storage(10000);
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
