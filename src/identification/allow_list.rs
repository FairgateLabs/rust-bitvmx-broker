use crate::{
    identification::{errors::IdentificationError, identifier::PubkHash},
    rpc::{errors::BrokerError, tls_helper::Cert},
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
    ) -> Result<Arc<Mutex<Self>>, BrokerError> {
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

    pub fn set_allow_all(&mut self, allow_all: bool) {
        self.allow_all = allow_all;
    }

    pub fn is_allow_all(&self) -> bool {
        self.allow_all
    }

    pub fn entries(&self) -> Vec<(PubkHash, Option<IpAddr>)> {
        self.allow_list
            .iter()
            .map(|(hash, addr)| (hash.clone(), *addr))
            .collect()
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

    pub fn add_entry(&mut self, pubk_hash: PubkHash, addr: Option<IpAddr>) {
        self.allow_list.insert(pubk_hash, addr);
    }

    pub fn remove(&mut self, pubk_hash: &PubkHash) {
        self.allow_list.remove(pubk_hash);
    }

    pub fn remove_by_cert(&mut self, cert: &Cert) -> Result<(), BrokerError> {
        let pubkey_hash = cert.get_pubk_hash()?;
        self.allow_list.remove(&pubkey_hash);
        Ok(())
    }
    pub fn add_by_cert(&mut self, cert: &Cert, addr: IpAddr) -> Result<(), BrokerError> {
        let pubkey_hash = cert.get_pubk_hash()?;
        self.allow_list.insert(pubkey_hash, Some(addr));
        Ok(())
    }
    pub fn add_by_certs(
        &mut self,
        certs: Vec<Cert>,
        addrs: Vec<IpAddr>,
    ) -> Result<(), BrokerError> {
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
        allow_list.add_entry("hash1".to_string(), Some(local_addr));
        allow_list.add_entry("hash2".to_string(), None);
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
        allow_list.set_allow_all(true);
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
            allow_list.add_entry("hashY".to_string(), addr_from_str("127.0.0.1"));
            allow_list
                .generate_yaml(file_path.to_str().unwrap())
                .unwrap();
        }

        let allow_list2 = AllowList::from_file(file_path.to_str().unwrap()).unwrap();
        let allow_list2 = allow_list2.lock().unwrap();
        assert!(allow_list2.is_allowed(&"hashY".to_string(), addr_from_str("127.0.0.1").unwrap()));
        assert!(
            !allow_list2.is_allowed(&"hashY".to_string(), addr_from_str("127.0.0.2").unwrap()),
            "the pinned address must survive the round trip, not widen to a wildcard",
        );
    }

    #[test]
    fn test_entries_reports_every_entry() {
        let local_addr = addr_from_str("127.0.0.1").unwrap();
        let allow_list = AllowList::new();
        let mut allow_list = allow_list.lock().unwrap();
        allow_list.add_entry("hash1".to_string(), Some(local_addr));
        allow_list.add_entry("hash2".to_string(), None);

        let mut entries = allow_list.entries();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                ("hash1".to_string(), Some(local_addr)),
                ("hash2".to_string(), None),
            ]
        );

        // entries() reports the list itself, independent of the blanket flag
        allow_list.set_allow_all(true);
        assert_eq!(allow_list.entries().len(), 2);
    }

    #[test]
    fn test_allow_all_can_be_cleared() {
        let local_addr = addr_from_str("127.0.0.1").unwrap();
        let allow_list = AllowList::new();
        let mut allow_list = allow_list.lock().unwrap();
        allow_list.add_entry("hash1".to_string(), Some(local_addr));

        allow_list.set_allow_all(true);
        assert!(allow_list.is_allow_all());
        assert!(allow_list.is_allowed(&"unknown".to_string(), local_addr));

        // clearing the flag makes the recorded entries operative again
        allow_list.set_allow_all(false);
        assert!(!allow_list.is_allow_all());
        assert!(allow_list.is_allowed(&"hash1".to_string(), local_addr));
        assert!(!allow_list.is_allowed(&"unknown".to_string(), local_addr));
    }

    #[test]
    fn test_add_entry_honours_optional_ip() {
        let local_addr = addr_from_str("127.0.0.1").unwrap();
        let other_addr = addr_from_str("127.0.0.2").unwrap();
        let allow_list = AllowList::new();
        let mut allow_list = allow_list.lock().unwrap();

        allow_list.add_entry("pinned".to_string(), Some(local_addr));
        allow_list.add_entry("wildcard".to_string(), None);

        assert!(allow_list.is_allowed(&"pinned".to_string(), local_addr));
        assert!(!allow_list.is_allowed(&"pinned".to_string(), other_addr));
        assert!(allow_list.is_allowed(&"wildcard".to_string(), local_addr));
        assert!(allow_list.is_allowed(&"wildcard".to_string(), other_addr));
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
