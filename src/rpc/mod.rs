use crate::{
    identification::identifier::Identifier,
    rpc::{
        config::BrokerSettings,
        errors::{BrokerError, BrokerRpcError},
        tls_helper::{init_tls, Cert},
    },
    settings::SERVER_ID,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
pub mod client;
pub mod client_async;
pub mod config;
pub mod errors;
pub mod rate_limiter;
pub mod server;
pub mod service;
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
    ip: IpAddr,
    listen_ip: IpAddr,
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
        init_tls(); // Ensure the CryptoProvider is initialized
                    //TODO: remove
        Self {
            port,
            ip: ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            listen_ip: ip.unwrap_or(IpAddr::V4(Ipv4Addr::from([0, 0, 0, 0]))),
            pubk_hash,
            broker_settings: broker_settings.unwrap_or_default(),
        }
    }

    // Do not use in production, this is for testing purposes
    pub fn new_only_address(
        port: u16,
        ip: Option<IpAddr>,
    ) -> Result<(Self, Identifier, Cert), BrokerError> {
        let cert = Cert::new()?;
        let pubk_hash = cert.get_pubk_hash()?;

        let identifier = Identifier {
            pubkey_hash: pubk_hash.clone(),
            id: SERVER_ID,
        };
        Ok((
            Self {
                port,
                ip: ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                listen_ip: ip.unwrap_or(IpAddr::V4(Ipv4Addr::from([0, 0, 0, 0]))),
                pubk_hash,
                broker_settings: BrokerSettings::default(),
            },
            identifier,
            cert,
        ))
    }

    pub fn get_pubk_hash(&self) -> String {
        self.pubk_hash.clone()
    }

    pub fn get_id(&self) -> u8 {
        SERVER_ID
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    pub fn get_address(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    pub fn get_ip(&self) -> IpAddr {
        self.ip
    }

    pub fn get_settings(&self) -> BrokerSettings {
        self.broker_settings.clone()
    }
}

