use std::net::IpAddr;

pub mod client;
pub mod server;
pub mod sync_server;

#[tarpc::service]
pub(crate) trait Broker {
    async fn send_msg(id: u32, msg: String) -> bool;
    async fn get_msg(id: u32) -> Vec<String>;
}

#[derive(Clone)]
pub struct BrokerConfig {
    pub port: u16,
    pub ip: Option<IpAddr>,
}

impl BrokerConfig {
    pub fn new(port: u16, ip: Option<IpAddr>) -> Self {
        Self { port, ip }
    }
}
