use std::net::SocketAddr;

use tokio::runtime::Runtime;

use super::BrokerConfig;
use crate::rpc::BrokerClient;
use tarpc::{client, context, tokio_serde::formats::Json};

pub struct Client {
    rt: Runtime,
    address: SocketAddr,
}

impl Client {
    pub fn new(config: BrokerConfig) -> Self {
        let rt = Runtime::new().unwrap();
        let address = SocketAddr::new(config.ip.unwrap(), config.port);
        Self { rt, address }
    }

    async fn aysnc_send_msg(&self, id: u32, msg: String) -> Result<bool, std::io::Error> {
        let mut transport = tarpc::serde_transport::tcp::connect(self.address, Json::default);
        transport.config_mut().max_frame_length(usize::MAX);
        let client = BrokerClient::new(client::Config::default(), transport.await?).spawn();
        let _ = client.send_msg(context::current(), id, msg).await;
        Ok(true)
    }

    async fn async_get_msg(&self, id: u32) -> Result<Vec<String>, std::io::Error> {
        let mut transport = tarpc::serde_transport::tcp::connect(self.address, Json::default);
        transport.config_mut().max_frame_length(usize::MAX);
        let client = BrokerClient::new(client::Config::default(), transport.await?).spawn();
        match client.get_msg(context::current(), id).await {
            Ok(msgs) => Ok(msgs),
            Err(_) => Ok(vec![]),
        }
    }

    pub fn send_msg(&self, id: u32, msg: String) -> bool {
        self.rt.block_on(self.aysnc_send_msg(id, msg)).unwrap()
    }

    pub fn get_msg(&self, id: u32) -> Vec<String> {
        self.rt.block_on(self.async_get_msg(id)).unwrap()
    }
}
