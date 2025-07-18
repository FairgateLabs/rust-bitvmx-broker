use crate::rpc::tls_helper::Cert;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, Mutex},
};
use tracing::info;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identifier {
    pub pubkey_hash: String,
    pub id: u8, // for internal services
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.pubkey_hash, self.id)
    }
}
impl From<(String, u8)> for Identifier {
    fn from(tuple: (String, u8)) -> Self {
        Identifier {
            pubkey_hash: tuple.0,
            id: tuple.1,
        }
    }
}

impl FromStr for Identifier {
    type Err = String;

    /// Parse format: "pubkey_hash:id"
    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err("Identifier must be in format 'name:id'".to_string());
        }
        let pubkey_hash = parts[0].to_string();
        let id: u8 = parts[1].parse::<u8>().map_err(|e| e.to_string())?;
        Ok(Identifier { pubkey_hash, id })
    }
}

#[derive(Debug)]
pub struct AllowList {
    allow_list: HashMap<Identifier, IpAddr>, // (pubkey_hash, id, IpAddr)
    allow_all: bool,                         // if true, all pubkey_hashes are allowed
}

impl AllowList {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            allow_list: HashMap::new(),
            allow_all: false,
        }))
    }
    pub fn from_file(allow_list_path: &str) -> Result<Arc<Mutex<Self>>, anyhow::Error> {
        let content = fs::read_to_string(allow_list_path)?;
        let allow_list: HashMap<Identifier, IpAddr> = serde_yaml::from_str(&content)?;
        Ok(Arc::new(Mutex::new(Self {
            allow_list,
            allow_all: false,
        })))
    }
    pub fn from_certs(
        certs: Vec<Cert>,
        addrs: Vec<IpAddr>,
    ) -> Result<Arc<Mutex<Self>>, anyhow::Error> {
        let mut allow_list = HashMap::new();
        for (cert, addr) in certs.into_iter().zip(addrs.into_iter()) {
            let pubkey_hash = cert.get_pubk_hash()?;
            allow_list.insert((pubkey_hash, 0).into(), addr);
        }
        Ok(Arc::new(Mutex::new(Self {
            allow_list,
            allow_all: false,
        })))
    }

    pub fn allow_all(&mut self) {
        self.allow_all = true;
    }
    pub fn is_allowed(&self, pubk_hash: &str, id: Option<u8>, addr: IpAddr) -> bool {
        if self.allow_all {
            return true;
        }
        let id = id.unwrap_or(0); // Default to 0 if no id is provided
        let key = Identifier {
            pubkey_hash: pubk_hash.to_string(),
            id,
        };
        match self.allow_list.get(&key) {
            Some(stored_addr) => *stored_addr == addr,
            None => false,
        }
    }
    pub fn is_allowed_no_id(&self, pubk_hash: &str, addr: IpAddr) -> bool {
        if self.allow_all {
            return true;
        }
        self.allow_list
            .iter()
            .any(|(ident, stored_addr)| ident.pubkey_hash == pubk_hash && *stored_addr == addr)
    }
    pub fn is_allowed_by_fingerprint(&self, pubk_hash: &str) -> bool {
        if self.allow_all {
            return true;
        }
        self.allow_list
            .keys()
            .any(|ident| ident.pubkey_hash == pubk_hash)
    }

    pub fn add(&mut self, pubk_hash: String, id: Option<u8>, addr: IpAddr) {
        let id = id.unwrap_or(0); // Default to 0 if no id is provided
        self.allow_list.insert(
            Identifier {
                pubkey_hash: pubk_hash,
                id,
            },
            addr,
        );
    }
    pub fn remove(&mut self, pubk_hash: &str, id: Option<u8>) {
        match id {
            Some(id_val) => {
                self.allow_list.remove(&Identifier {
                    pubkey_hash: pubk_hash.to_string(),
                    id: id_val,
                });
            }
            None => {
                // Remove all entries with the given pubkey_hash
                let keys_to_remove: Vec<_> = self
                    .allow_list
                    .keys()
                    .filter(|ident| ident.pubkey_hash == pubk_hash)
                    .cloned()
                    .collect();
                for key in keys_to_remove {
                    self.allow_list.remove(&key);
                }
            }
        }
    }

    pub fn remove_by_cert(&mut self, cert: &Cert, id: Option<u8>) -> Result<(), anyhow::Error> {
        let pubkey_hash = cert.get_pubk_hash()?;
        let id = id.unwrap_or(0); // Default to 0 if no id is provided
        self.allow_list.remove(&Identifier { pubkey_hash, id });
        Ok(())
    }
    pub fn add_by_cert(
        &mut self,
        cert: &Cert,
        id: Option<u8>,
        addr: IpAddr,
    ) -> Result<(), anyhow::Error> {
        let pubkey_hash = cert.get_pubk_hash()?;
        let id = id.unwrap_or(0); // Default to 0 if no id is provided
        self.allow_list.insert(Identifier { pubkey_hash, id }, addr);
        Ok(())
    }
    pub fn add_by_certs(
        &mut self,
        certs: Vec<Cert>,
        addrs: Vec<IpAddr>,
    ) -> Result<(), anyhow::Error> {
        for (cert, addr) in certs.into_iter().zip(addrs.into_iter()) {
            self.add_by_cert(&cert, None, addr)?;
        }
        Ok(())
    }

    pub fn generate_yaml(&self, path: &str) -> Result<(), anyhow::Error> {
        let yaml = serde_yaml::to_string(&self.allow_list)?;
        fs::write(path, yaml)?;
        info!("Allow list saved to allowlist.yaml");
        Ok(())
    }

    pub fn get_pubk_hash_from_privk(privk: &str) -> Result<String, anyhow::Error> {
        let cert = Cert::new_with_privk(privk)?;
        cert.get_pubk_hash()
    }
}
