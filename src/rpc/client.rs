use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::{net::TcpStream, runtime::Runtime};

use super::{errors::BrokerError, BrokerConfig, Message};
use crate::rpc::BrokerClient;
use tarpc::{client, context, serde_transport, tokio_serde::formats::Json};

pub struct Client {
    rt: Runtime,
    client: BrokerClient,
}

impl Client {
    pub fn new(config: &BrokerConfig) -> Self {
        let rt = Runtime::new().unwrap();
        let address = SocketAddr::new(
            config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            config.port,
        );

        // Connect and initialize the client once
        let client_future = async {
            let stream = TcpStream::connect(address).await?;
            stream.set_nodelay(true)?;
            let transport = serde_transport::Transport::from((stream, Json::default()));
            let client = BrokerClient::new(client::Config::default(), transport).spawn();
            Ok::<_, anyhow::Error>(client)
        };

        let client = rt
            .block_on(client_future)
            .expect("Failed to connect to broker");

        Self { rt, client }
    }

    async fn async_send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        Ok(self
            .client
            .send(context::current(), from, dest, msg)
            .await?)
    }

    async fn async_get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        Ok(self.client.get(context::current(), dest).await?)
    }

    async fn async_ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        Ok(self.client.ack(context::current(), dest, uid).await?)
    }

    pub fn send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_send_msg(from, dest, msg))
    }

    pub fn get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        self.rt.block_on(self.async_get_msg(dest))
    }

    pub fn ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_ack(dest, uid))
    }
}
