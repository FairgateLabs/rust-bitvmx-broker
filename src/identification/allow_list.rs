use crate::{
    identification::{
        errors::IdentificationError,
        identifier::{Identifier, PubkHash},
    },
    rpc::tls_helper::Cert,
};
use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tracing::info;

#[derive(Debug)]
pub struct AllowList {
    allow_list: HashMap<PubkHash, IpAddr>, // (pubkey_hash, id, IpAddr)
    allow_all: bool,                       // if true, all pubkey_hashes are allowed
}

impl AllowList {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            allow_list: HashMap::new(),
            allow_all: false,
        }))
    }
    pub fn from_file(allow_list_path: &str) -> Result<Arc<Mutex<Self>>, IdentificationError> {
        let content = fs::read_to_string(allow_list_path)?;
        if content == "allow_all" {
            return Ok(Arc::new(Mutex::new(Self {
                allow_list: HashMap::new(),
                allow_all: true,
            })));
        }
        let allow_list: HashMap<PubkHash, IpAddr> = serde_yaml::from_str(&content)?;
        Ok(Arc::new(Mutex::new(Self {
            allow_list,
            allow_all: false,
        })))
    }
    pub fn from_certs(
        certs: Vec<Cert>,
        addrs: Vec<IpAddr>,
    ) -> Result<Arc<Mutex<Self>>, IdentificationError> {
        let mut allow_list = HashMap::new();
        for (cert, addr) in certs.into_iter().zip(addrs.into_iter()) {
            let pubkey_hash = cert.get_pubk_hash()?;
            allow_list.insert(pubkey_hash, addr);
        }
        Ok(Arc::new(Mutex::new(Self {
            allow_list,
            allow_all: false,
        })))
    }

    pub fn from_identifiers(
        identifiers: Vec<Identifier>,
    ) -> Result<Arc<Mutex<Self>>, IdentificationError> {
        let mut allow_list = HashMap::new();
        for identifier in identifiers.into_iter() {
            allow_list.insert(identifier.pubkey_hash, identifier.ip);
        }
        Ok(Arc::new(Mutex::new(Self {
            allow_list,
            allow_all: false,
        })))
    }

    pub fn allow_all(&mut self) {
        self.allow_all = true;
    }
    pub fn is_allowed(&self, pubk_hash: &PubkHash, addr: IpAddr) -> bool {
        if self.allow_all {
            return true;
        }
        match self.allow_list.get(pubk_hash) {
            Some(stored_addr) => *stored_addr == addr,
            None => false,
        }
    }
    pub fn is_allowed_by_fingerprint(&self, pubk_hash: &str) -> bool {
        if self.allow_all {
            return true;
        }
        self.allow_list
            .keys()
            .any(|pubkey_hash| pubkey_hash == pubk_hash)
    }

    pub fn add(&mut self, pubk_hash: String, addr: IpAddr) {
        self.allow_list.insert(pubk_hash, addr);
    }
    pub fn remove(&mut self, pubk_hash: &str) {
        self.allow_list.remove(pubk_hash);
    }

    pub fn remove_by_cert(&mut self, cert: &Cert) -> Result<(), IdentificationError> {
        let pubkey_hash = cert.get_pubk_hash()?;
        self.allow_list.remove(&pubkey_hash);
        Ok(())
    }
    pub fn add_by_cert(&mut self, cert: &Cert, addr: IpAddr) -> Result<(), IdentificationError> {
        let pubkey_hash = cert.get_pubk_hash()?;
        self.allow_list.insert(pubkey_hash, addr);
        Ok(())
    }
    pub fn add_by_certs(
        &mut self,
        certs: Vec<Cert>,
        addrs: Vec<IpAddr>,
    ) -> Result<(), IdentificationError> {
        for (cert, addr) in certs.into_iter().zip(addrs.into_iter()) {
            self.add_by_cert(&cert, addr)?;
        }
        Ok(())
    }

    pub fn generate_yaml(&self, path: &str) -> Result<(), IdentificationError> {
        let yaml = serde_yaml::to_string(&self.allow_list)?;
        fs::write(path, yaml)?;
        info!("Allow list saved to allowlist.yaml");
        Ok(())
    }

    pub fn get_pubk_hash_from_privk(privk: &str) -> Result<String, IdentificationError> {
        let cert = Cert::new_with_privk(privk)?;
        Ok(cert.get_pubk_hash()?)
    }
}
