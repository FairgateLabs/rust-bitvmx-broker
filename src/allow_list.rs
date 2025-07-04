use std::{
    collections::HashSet,
    fs,
    sync::{Arc, Mutex},
};

use anyhow::Ok;
use tracing::info;

use crate::rpc::tls_helper::Cert;

#[derive(Debug)]
pub struct AllowList {
    allow_list: HashSet<String>, // pubkey_hash
}

impl AllowList {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            allow_list: HashSet::new(),
        }))
    }

    pub fn from_file(allow_list_path: String) -> Result<Arc<Mutex<Self>>, anyhow::Error> {
        let content = fs::read_to_string(allow_list_path)?;
        let allow_list: HashSet<String> = serde_yaml::from_str(&content)?;
        Ok(Arc::new(Mutex::new(Self { allow_list })))
    }

    pub fn from_certs(certs: Vec<Cert>) -> Result<Arc<Mutex<Self>>, anyhow::Error> {
        let mut allow_list = HashSet::new();
        for cert in certs {
            let pubkey_hash = cert.get_pubk_hash()?;
            allow_list.insert(pubkey_hash);
        }
        Ok(Arc::new(Mutex::new(Self { allow_list })))
    }

    pub fn is_allowed(&self, key: &str) -> bool {
        self.allow_list.contains(key)
    }

    pub fn add(&mut self, key: String) {
        self.allow_list.insert(key);
    }

    pub fn remove(&mut self, key: &str) {
        self.allow_list.remove(key);
    }

    pub fn remove_by_cert(&mut self, cert: &Cert) -> Result<(), anyhow::Error> {
        let pubkey_hash = cert.get_pubk_hash()?;
        self.allow_list.remove(&pubkey_hash);
        Ok(())
    }

    pub fn add_by_cert(&mut self, cert: &Cert) -> Result<(), anyhow::Error> {
        let pubkey_hash = cert.get_pubk_hash()?;
        self.allow_list.insert(pubkey_hash);
        Ok(())
    }

    pub fn generate_yaml(&self, file_name: &str) -> Result<(), anyhow::Error> {
        let yaml = serde_yaml::to_string(&self.allow_list)?;
        let path = format!("certs/{}.yaml", file_name);
        fs::write(path, yaml)?;
        info!("Allow list saved to allowlist.yaml");
        Ok(())
    }
}
