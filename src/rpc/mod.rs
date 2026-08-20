use crate::{
    identification::identifier::Identifier,
    rpc::{
        config::BrokerSettings,
        errors::{BrokerError, BrokerRpcError},
        tls_helper::Cert,
    },
    settings::SERVER_ID,
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
    server_port: u16,
    server_ip: Option<IpAddr>,
    broker_settings: BrokerSettings,
}

impl BrokerConfig {
    pub fn new(
        server_port: u16,
        server_ip: Option<IpAddr>,
        broker_settings: Option<BrokerSettings>,
    ) -> Self {
        Self {
            server_port,
            server_ip,
            broker_settings: broker_settings.unwrap_or_default(),
        }
    }

    // Do not use in production, this is for testing purposes
    pub fn new_only_address(
        server_port: u16,
        server_ip: Option<IpAddr>,
    ) -> Result<(Self, Identifier, Cert), BrokerError> {
        let cert = Cert::new()?;
        let identifier = Identifier::new(cert.get_pubk_hash()?, SERVER_ID);
        Ok((Self::new(server_port, server_ip, None), identifier, cert))
    }

    /// Where the server listens. An unspecified address means every interface.
    pub fn bind_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.server_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            self.server_port,
        )
    }

    /// Where a client connects. An unspecified address means this machine.
    pub fn dial_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.server_ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            self.server_port,
        )
    }

    pub fn get_settings(&self) -> BrokerSettings {
        self.broker_settings.clone()
    }
}
