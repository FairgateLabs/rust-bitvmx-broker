use crate::{
    identification::identifier::Identifier,
    rpc::{config::BrokerSettings, errors::BrokerRpcError},
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
pub(crate) mod api_impl;
pub mod client;
pub mod client_async;
pub mod config;
pub mod errors;
pub mod rate_limiter;
pub mod server;
pub mod tls_helper;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub uid: u64,
    pub from: Identifier,
    pub msg: String,
}

#[tarpc::service]
pub(crate) trait BrokerApi {
    async fn send(from_id: u8, dest: Identifier, msg: String) -> Result<bool, BrokerRpcError>;
    async fn get(dest_id: u8) -> Result<Option<Message>, BrokerRpcError>;
    async fn ack(dest_id: u8, uid: u64) -> Result<bool, BrokerRpcError>;
    async fn ping() -> Result<bool, BrokerRpcError>;
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BrokerConfig {
    port: u16,
    ip: Option<IpAddr>, //A server left unspecified listens everywhere and a client left unspecified dials this machine.
    pubk_hash: String,
    broker_settings: BrokerSettings,
}

impl BrokerConfig {
    pub fn new(
        port: u16,
        ip: Option<IpAddr>,
        pubk_hash: String,
        broker_settings: Option<BrokerSettings>,
    ) -> Self {
        Self {
            port,
            ip,
            pubk_hash,
            broker_settings: broker_settings.unwrap_or_default(),
        }
    }

    pub fn get_pubk_hash(&self) -> String {
        self.pubk_hash.clone()
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    /// Where a server listens.
    pub fn bind_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            self.port,
        )
    }

    /// Where a client connects.
    pub fn dial_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            self.port,
        )
    }

    pub fn get_ip(&self) -> Option<IpAddr> {
        self.ip
    }

    pub fn get_settings(&self) -> BrokerSettings {
        self.broker_settings.clone()
    }
}
