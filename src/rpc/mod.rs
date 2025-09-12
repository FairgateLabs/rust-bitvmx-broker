use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub mod async_client;
pub mod client;
pub mod errors;
pub mod server;
pub mod sync_server;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub uid: u64,
    pub from: u32,
    pub msg: String,
}

#[tarpc::service]
pub(crate) trait Broker {
    async fn send(from: u32, dest: u32, msg: String) -> bool;
    async fn get(dest: u32) -> Option<Message>;
    async fn ack(dest: u32, uid: u64) -> bool;
}

#[derive(Clone)]
pub struct BrokerConfig {
    pub port: u16,
    pub ip: Option<IpAddr>,
}

impl BrokerConfig {
    pub fn new(port: u16, ip: Option<IpAddr>) -> Self {
        Self { port, ip }
    }
}

pub trait StorageApi {
    fn get(&mut self, dest: u32) -> Option<Message>;
    fn insert(&mut self, from: u32, dest: u32, msg: String);
    fn remove(&mut self, dest: u32, uid: u64) -> bool;
}
