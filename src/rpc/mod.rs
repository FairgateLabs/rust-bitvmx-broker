use crate::{allow_list::Identifier, rpc::errors::BrokerError};
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
    pub from: Identifier,
    pub msg: String,
}

#[tarpc::service]
pub(crate) trait Broker {
    async fn send(from: Identifier, dest: Identifier, msg: String) -> bool;
    async fn get(dest: Identifier) -> Option<Message>;
    async fn ack(dest: Identifier, uid: u64) -> bool;
    async fn ping() -> bool;
}

#[derive(Clone)]
pub struct BrokerConfig {
    port: u16,
    ip: Option<IpAddr>,
    pubk_hash: String,
    id: u8,
}

impl BrokerConfig {
    pub fn new(
        port: u16,
        ip: Option<IpAddr>,
        pubk_hash: String,
        id: Option<u8>,
    ) -> Result<Self, BrokerError> {
        Ok(Self {
            port,
            ip,
            pubk_hash,
            id: id.unwrap_or(0), // Default to 0 if not provided
        })
    }

    pub fn get_pubk_hash(&self) -> String {
        self.pubk_hash.clone()
    }

    pub fn get_id(&self) -> u8 {
        self.id
    }
}

pub trait StorageApi {
    fn get(&mut self, dest: Identifier) -> Option<Message>;
    fn insert(&mut self, from: Identifier, dest: Identifier, msg: String);
    fn remove(&mut self, dest: Identifier, uid: u64) -> bool;
}
