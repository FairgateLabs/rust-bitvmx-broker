use crate::{
    identification::identifier::Identifier,
    rpc::{
        errors::BrokerError,
        tls_helper::{init_tls, Cert},
    },
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    async fn send(from_id: u8, from_port: u16, dest: Identifier, msg: String) -> bool;
    async fn get(dest: Identifier) -> Option<Message>;
    async fn ack(dest: Identifier, uid: u64) -> bool;
    async fn ping() -> bool;
}

#[derive(Clone, Serialize, Deserialize, Debug)]
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
        init_tls(); // Ensure the CryptoProvider is initialized
                    //TODO: remove
        Ok(Self {
            port,
            ip,
            pubk_hash,
            id: id.unwrap_or(0), // Default to 0 if not provided
        })
    }

    // Do not use in production, this is for testing purposes
    pub fn new_only_address(
        port: u16,
        ip: Option<IpAddr>,
    ) -> Result<(Self, Identifier, Cert), BrokerError> {
        let id = 0; // Default to 0 if not provided
        let cert = Cert::new()?;
        let pubk_hash = cert.get_pubk_hash()?;

        let identifier = Identifier {
            pubkey_hash: pubk_hash.clone(),
            id: Some(id),
            address: SocketAddr::new(ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)), port),
        };
        Ok((
            Self {
                port,
                ip,
                pubk_hash,
                id,
            },
            identifier,
            cert,
        ))
    }

    pub fn get_pubk_hash(&self) -> String {
        self.pubk_hash.clone()
    }

    pub fn get_id(&self) -> u8 {
        self.id
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    pub fn get_address(&self) -> SocketAddr {
        SocketAddr::new(
            self.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            self.port,
        )
    }
}

pub trait StorageApi {
    fn get(&mut self, dest: Identifier) -> Option<Message>;
    fn insert(&mut self, from: Identifier, dest: Identifier, msg: String);
    fn remove(&mut self, dest: Identifier, uid: u64) -> bool;
}
