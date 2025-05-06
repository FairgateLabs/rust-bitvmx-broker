use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tls_helper::CertFiles;

pub mod client;
pub mod errors;
pub mod server;
pub mod sync_server;
pub mod tls_helper;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub uid: u64,
    pub from: u32,
    pub msg: String,
}

#[tarpc::service]
pub(crate) trait Broker {
    async fn send(from: u32, dest: u32, msg: String) -> bool;
    async fn get(dest: u32) -> Option<Message>;
    async fn ack(dest: u32, uid: u64) -> bool;
}

#[derive(Clone)]
pub struct BrokerConfig {
    pub port: u16,
    pub ip: Option<IpAddr>,
    pub cert_files: CertFiles,
}

impl BrokerConfig {
    pub fn new(port: u16, ip: Option<IpAddr>, cert_files: CertFiles) -> Self {
        Self {
            port,
            ip,
            cert_files,
        }
    }

    /// ⚠️ Test-only helper.
    /// Loads certs from `certs/` folder using provided `name`.
    pub fn get_local_cert_files(name: &str) -> CertFiles {
        let cert = format!("certs/{}.pem", name);
        let key = format!("certs/{}.key", name);
        let allow_list = "certs/allowlist.yaml".to_string();
        CertFiles::new(allow_list, cert, key)
    }
}

pub trait StorageApi {
    fn get(&mut self, dest: u32) -> Option<Message>;
    fn insert(&mut self, from: u32, dest: u32, msg: String);
    fn remove(&mut self, dest: u32, uid: u64) -> bool;
}
