use crate::{
    identification::{errors::IdentificationError, identifier::PubkHash},
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
    allow_list: HashMap<PubkHash, Option<IpAddr>>, // (pubkey_hash, IpAddr). None means wildcard for IP
    allow_all: bool,                               // if true, all pubkey_hashes are allowed
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
        Self::parse_yaml(&content)
    }
    fn parse_yaml(yaml_str: &str) -> Result<Arc<Mutex<Self>>, IdentificationError> {
        let allow_list: HashMap<PubkHash, Option<IpAddr>> = serde_yaml::from_str(&yaml_str)?;
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
            allow_list.insert(pubkey_hash, Some(addr));
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
            Some(stored_addr) => match stored_addr {
                Some(a) => *a == addr,
                None => true,
            },
            None => false,
        }
    }
    pub fn is_allowed_by_fingerprint(&self, pubk_hash: &PubkHash) -> bool {
        if self.allow_all {
            return true;
        }
        self.allow_list
            .keys()
            .any(|pubkey_hash| pubkey_hash == pubk_hash)
    }

    pub fn add(&mut self, pubk_hash: PubkHash, addr: IpAddr) {
        self.allow_list.insert(pubk_hash, Some(addr));
    }

    pub fn add_wildcard(&mut self, pubk_hash: PubkHash) {
        self.allow_list.insert(pubk_hash, None);
    }

    pub fn remove(&mut self, pubk_hash: &PubkHash) {
        self.allow_list.remove(pubk_hash);
    }

    pub fn remove_by_cert(&mut self, cert: &Cert) -> Result<(), IdentificationError> {
        let pubkey_hash = cert.get_pubk_hash()?;
        self.allow_list.remove(&pubkey_hash);
        Ok(())
    }
    pub fn add_by_cert(&mut self, cert: &Cert, addr: IpAddr) -> Result<(), IdentificationError> {
        let pubkey_hash = cert.get_pubk_hash()?;
        self.allow_list.insert(pubkey_hash, Some(addr));
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

#[cfg(test)]
mod tests {
    use crate::identification::allow_list::AllowList;
    use std::{fs, net::IpAddr};
    use tempfile::tempdir;

    #[test]
    fn test_allowed() {
        let local_addr = addr_from_str("127.0.0.1").unwrap();
        let allow_list = AllowList::new();
        let mut allow_list = allow_list.lock().unwrap();
        allow_list.add("hash1".to_string(), local_addr);
        allow_list.add_wildcard("hash2".to_string());
        assert!(allow_list.is_allowed(&"hash1".to_string(), local_addr));
        assert!(allow_list.is_allowed(&"hash2".to_string(), local_addr));
        assert!(!allow_list.is_allowed(&"hash1".to_string(), addr_from_str("127.0.0.2").unwrap()));
        assert!(!allow_list.is_allowed(&"hash3".to_string(), local_addr));
        assert!(allow_list.is_allowed_by_fingerprint(&"hash1".to_string()));
        assert!(!allow_list.is_allowed_by_fingerprint(&"hash3".to_string()));
        allow_list.remove(&"hash1".to_string());
        assert!(!allow_list.is_allowed_by_fingerprint(&"hash1".to_string()));
        assert!(!allow_list.is_allowed(&"hash".to_string(), local_addr));
    }

    #[test]
    fn test_allow_all_flag() {
        let allow_list = AllowList::new();
        let mut allow_list = allow_list.lock().unwrap();
        allow_list.allow_all();
        assert!(allow_list.allow_all);
        assert!(allow_list.is_allowed(&"anything".to_string(), addr_from_str("127.0.0.1").unwrap()));
    }

    #[test]
    fn test_from_file_allow_all() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("allowlist.yaml");
        fs::write(&file_path, "allow_all").unwrap();
        let allow_list = AllowList::from_file(file_path.to_str().unwrap()).unwrap();
        let allow_list = allow_list.lock().unwrap();
        assert!(allow_list.allow_all);
    }

    #[test]
    fn test_generate_yaml_and_reload() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("out.yaml");

        let allow_list = AllowList::new();
        {
            let mut allow_list = allow_list.lock().unwrap();
            allow_list.add("hashY".to_string(), addr_from_str("127.0.0.1").unwrap());
            allow_list
                .generate_yaml(file_path.to_str().unwrap())
                .unwrap();
        }

        let allow_list2 = AllowList::from_file(file_path.to_str().unwrap()).unwrap();
        let allow_list2 = allow_list2.lock().unwrap();
        assert!(allow_list2.is_allowed(&"hashY".to_string(), addr_from_str("127.0.0.1").unwrap()));
    }

    #[test]
    fn test_format() {
        let yaml = vec!["pubk1: 127.0.0.1", "pubk2: ~"].join("\n");
        AllowList::parse_yaml(&yaml).expect("Failed to parse allow list");
    }

    fn addr_from_str(s: &str) -> Option<IpAddr> {
        s.parse::<IpAddr>().ok()
    }
}
