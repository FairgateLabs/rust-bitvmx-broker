use crate::{
    identification::identifier::Identifier,
    rpc::{
        errors::{BrokerError, BrokerRpcError},
        tls_helper::{init_tls, Cert},
    },
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
pub mod client;
pub mod errors;
pub mod rate_limiter;
pub mod server;
pub mod sync_client;
pub mod sync_server;
pub mod tls_helper;

pub const MAX_FRAME_SIZE_KB: usize = 1024; // NOTE: `MAX_FRAME_SIZE_KB` applies to the entire
                                           // encoded frame, not just the message payload
                                           // As a result, the maximum allowed `msg` payload
                                           // must be strictly smaller than this limit.
pub const MAX_MSG_SIZE_KB: usize = MAX_FRAME_SIZE_KB - 4; // Leave some room for encoding overhead
const SERVER_ID: u8 = 0; // Default ID for the server

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub uid: u64,
    pub from: Identifier,
    pub msg: String,
}

#[tarpc::service]
pub(crate) trait Broker {
    async fn send(from_id: u8, dest: Identifier, msg: String) -> Result<bool, BrokerRpcError>;
    async fn get(dest_id: u8) -> Result<Option<Message>, BrokerRpcError>;
    async fn ack(dest_id: u8, uid: u64) -> Result<bool, BrokerRpcError>;
    async fn ping() -> Result<bool, BrokerRpcError>;
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BrokerConfig {
    port: u16,
    ip: Option<IpAddr>,
    pubk_hash: String,
}

impl BrokerConfig {
    pub fn new(port: u16, ip: Option<IpAddr>, pubk_hash: String) -> Self {
        init_tls(); // Ensure the CryptoProvider is initialized
                    //TODO: remove
        Self {
            port,
            ip,
            pubk_hash,
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
                ip,
                pubk_hash,
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
        SocketAddr::new(
            self.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            self.port,
        )
    }

    pub fn get_ip(&self) -> IpAddr {
        self.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }
}

pub trait StorageApi {
    fn get(&mut self, dest: Identifier) -> Result<Option<Message>, BrokerRpcError>;
    fn insert(
        &mut self,
        from: Identifier,
        dest: Identifier,
        msg: String,
    ) -> Result<(), BrokerRpcError>;
    fn remove(&mut self, dest: Identifier, uid: u64) -> Result<bool, BrokerRpcError>;
}
