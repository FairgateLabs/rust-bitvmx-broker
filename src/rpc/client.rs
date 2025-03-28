use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::runtime::Runtime;

use super::{errors::BrokerError, BrokerConfig, Message};
use crate::rpc::BrokerClient;
use tarpc::{client, context, tokio_serde::formats::Json};

#[derive(Clone)]
pub struct Client {
    rt: Arc<Runtime>,
    address: SocketAddr,
}

impl Client {
    pub fn new(config: &BrokerConfig) -> Self {
        let rt = Arc::new(Runtime::new().unwrap());
        let address = SocketAddr::new(
            config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            config.port,
        );
        Self { rt, address }
    }

    async fn aysnc_send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        let mut transport = tarpc::serde_transport::tcp::connect(self.address, Json::default);
        transport.config_mut().max_frame_length(usize::MAX);
        let client = BrokerClient::new(client::Config::default(), transport.await?).spawn();
        Ok(client.send(context::current(), from, dest, msg).await?)
    }

    async fn async_get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        let mut transport = tarpc::serde_transport::tcp::connect(self.address, Json::default);
        transport.config_mut().max_frame_length(usize::MAX);
        let client = BrokerClient::new(client::Config::default(), transport.await?).spawn();
        Ok(client.get(context::current(), dest).await?)
    }

    async fn async_ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        let mut transport = tarpc::serde_transport::tcp::connect(self.address, Json::default);
        transport.config_mut().max_frame_length(usize::MAX);
        let client = BrokerClient::new(client::Config::default(), transport.await?).spawn();
        Ok(client.ack(context::current(), dest, uid).await?)
    }

    pub fn send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        self.rt.block_on(self.aysnc_send_msg(from, dest, msg))
    }

    pub fn get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        self.rt.block_on(self.async_get_msg(dest))
    }

    pub fn ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_ack(dest, uid))
    }
}
