use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

use bitvmx_broker::{
    channel::channel::DualChannel,
    rpc::{client::Client, sync_server::BrokerSync, BrokerConfig, Message, StorageApi},
};

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

fn prepare(port: u16) -> (BrokerSync, Arc<Mutex<MemStorage>>, BrokerConfig) {
    let storage = Arc::new(Mutex::new(MemStorage::new()));
    let config = BrokerConfig::new(port, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server = BrokerSync::new(&config, storage.clone());
    (server, storage, config)
}

#[test]
fn test_channel() {
    let (mut server, _, config) = prepare(10000);
    let user_1 = DualChannel::new(&config, 1);
    let user_2 = DualChannel::new(&config, 2);

    user_1.send(2, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();
    assert_eq!(msg, "Hello!");
    server.close();
}

#[test]
fn test_ack() {
    let (mut server, _, config) = prepare(10001);

    let client = Client::new(&config);
    client.send_msg(1, 2, "Hello!".to_string()).unwrap();

    let msg = client.get_msg(2).unwrap().unwrap();
    assert_eq!(msg.msg, "Hello!");
    let msg_dup = client.get_msg(2).unwrap().unwrap();
    assert_eq!(msg.uid, msg_dup.uid);
    assert!(client.ack(2, msg.uid).unwrap());
    assert!(client.get_msg(2).unwrap().is_none());
    server.close();
}
