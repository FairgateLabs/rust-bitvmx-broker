use crate::{
    identification::identifier::Identifier,
    rpc::{
        config::{BrokerSettings, MsgSizeConfig},
        errors::BrokerRpcError,
    },
    settings::FRAME_ENVELOPE_RESERVE_KB,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::warn;
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

/// Refuses a payload that would not fit in a frame. The payload travels as a JSON string.
pub(crate) fn ensure_msg_fits(msg: &str, config: &MsgSizeConfig) -> Result<(), BrokerRpcError> {
    let budget = config
        .max_frame_size_kb
        .saturating_sub(FRAME_ENVELOPE_RESERVE_KB)
        * 1024;
    let needed = serde_json::to_string(msg)
        .map_err(|e| BrokerRpcError::ParseError(e.to_string()))?
        .len();

    if needed > budget {
        warn!("Message too large: {} bytes encoded", needed);
        return Err(BrokerRpcError::MessageTooLarge(
            budget / 1024,
            needed.div_ceil(1024),
        ));
    }
    Ok(())
}
