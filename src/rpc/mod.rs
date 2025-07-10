use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    allow_list::AllowList,
    rpc::{errors::BrokerError, tls_helper::Cert},
};

pub mod client;
pub mod errors;
pub mod server;
pub mod sync_server;
pub mod tls_helper;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub uid: u64,
    pub from: String, // Public key hash
    pub msg: String,
}

#[tarpc::service]
pub(crate) trait Broker {
    async fn send(from: String, dest: String, msg: String) -> bool;
    async fn get(dest: String) -> Option<Message>;
    async fn ack(dest: String, uid: u64) -> bool;
}

#[derive(Clone)]
pub struct BrokerConfig {
    port: u16,
    ip: Option<IpAddr>,
    cert: Cert,
    allow_list: Arc<Mutex<AllowList>>,
}

impl BrokerConfig {
    pub fn new(
        port: u16,
        ip: Option<IpAddr>,
        cert: Cert,
        allow_list: Arc<Mutex<AllowList>>,
    ) -> Result<Self, BrokerError> {
        Ok(Self {
            port,
            ip,
            cert,
            allow_list,
        })
    }

    // /// ⚠️ Test-only helper.
    // /// Loads certs from `certs/` folder using provided `name`.
    pub fn _get_local_cert_files(name: &str) -> Cert {
        Cert::from_file("./certs", name).unwrap()
    }
    pub fn _get_allow_list_from_file() -> Result<Arc<Mutex<AllowList>>, BrokerError> {
        let allow_list = "allowlist.yaml".to_string();
        let allow_list = AllowList::from_file(allow_list)?;
        Ok(allow_list)
    }
    pub fn get_cert(&self) -> Cert {
        self.cert.clone()
    }
}

pub trait StorageApi {
    fn get(&mut self, dest: String) -> Option<Message>;
    fn insert(&mut self, from: String, dest: String, msg: String);
    fn remove(&mut self, dest: String, uid: u64) -> bool;
}
