use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Mutex},
};

use anyhow::Ok;
use tracing::info;

use crate::rpc::tls_helper::Cert;

#[derive(Debug)]
pub struct AllowList {
    allow_list: HashMap<String, String>, // (pubkey_hash, name)
}

impl AllowList {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            allow_list: HashMap::new(),
        }))
    }

    pub fn from_file(allow_list_path: String) -> Result<Arc<Mutex<Self>>, anyhow::Error> {
        let content = fs::read_to_string(allow_list_path)?;
        let allow_list: HashMap<String, String> = serde_yaml::from_str(&content)?;
        Ok(Arc::new(Mutex::new(Self { allow_list })))
    }

    pub fn from_certs(certs: Vec<Cert>) -> Result<Arc<Mutex<Self>>, anyhow::Error> {
        let mut allow_list = HashMap::new();
        for cert in certs {
            let pubkey_hash = cert.get_pubk_hash()?;
            let name = cert.get_name();
            allow_list.insert(pubkey_hash, name);
        }
        Ok(Arc::new(Mutex::new(Self { allow_list })))
    }

    pub fn is_allowed(&self, key: &str) -> bool {
        self.allow_list.contains_key(key)
    }

    pub fn add(&mut self, key: String, value: String) {
        self.allow_list.insert(key, value);
    }

    pub fn remove(&mut self, key: &str) {
        self.allow_list.remove(key);
    }

    pub fn remove_by_value(&mut self, value: &str) -> Option<(String, String)> {
        if let Some(key) = self
            .allow_list
            .iter()
            .find(|(_, v)| v == &value)
            .map(|(k, _)| k.clone())
        {
            self.allow_list.remove(&key).map(|value| (key, value))
        } else {
            None
        }
    }
}
