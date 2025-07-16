use crate::rpc::errors::BrokerError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
pub mod client;
pub mod errors;
pub mod server;
pub mod sync_server;
pub mod tls_helper;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub uid: u64,
    pub from: String, // Public key hash
    pub msg: String,
}

#[tarpc::service]
pub(crate) trait Broker {
    async fn send(from: String, dest: String, msg: String) -> bool;
    async fn get(dest: String) -> Option<Message>;
    async fn ack(dest: String, uid: u64) -> bool;
}

#[derive(Clone)]
pub struct BrokerConfig {
    port: u16,
    ip: Option<IpAddr>,
    pubk_hash: String,
}

impl BrokerConfig {
    pub fn new(port: u16, ip: Option<IpAddr>, pubk_hash: String) -> Result<Self, BrokerError> {
        Ok(Self {
            port,
            ip,
            pubk_hash,
        })
    }

    pub fn get_pubk_hash(&self) -> String {
        self.pubk_hash.clone()
    }
}

pub trait StorageApi {
    fn get(&mut self, dest: String) -> Option<Message>;
    fn insert(&mut self, from: String, dest: String, msg: String);
    fn remove(&mut self, dest: String, uid: u64) -> bool;
}
