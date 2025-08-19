use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

pub type PubkHash = String;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identifier {
    pub pubkey_hash: PubkHash,
    pub id: Option<u8>, // For internal services. `None` represents a wildcard '*'
    pub address: SocketAddr,
}

impl Identifier {
    pub fn new(pubkey_hash: PubkHash, id: u8, address: SocketAddr) -> Self {
        Identifier {
            pubkey_hash,
            id: Some(id),
            address,
        }
    }
    pub fn new_local(pubkey_hash: PubkHash, id: u8, port: u16) -> Self {
        Identifier {
            pubkey_hash,
            id: Some(id),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        }
    }
}

impl From<(String, Option<u8>, SocketAddr)> for Identifier {
    fn from(tuple: (String, Option<u8>, SocketAddr)) -> Self {
        Identifier {
            pubkey_hash: tuple.0,
            id: tuple.1,
            address: tuple.2,
        }
    }
}

impl FromStr for Identifier {
    type Err = String;

    /// Parse format: "pubkey_hash:id@address"
    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('@').collect();
        if parts.len() != 2 {
            return Err("Identifier must be in format 'pubkey_hash:id@address'".to_string());
        }

        let id_parts: Vec<&str> = parts[0].split(':').collect();
        if id_parts.len() != 2 {
            return Err("Identifier must be in format 'pubkey_hash:id@address'".to_string());
        }

        let pubkey_hash = id_parts[0].to_string();
        let id = if id_parts[1] == "*" {
            None
        } else {
            Some(id_parts[1].parse::<u8>().map_err(|e| e.to_string())?)
        };

        let address = parts[1].parse::<SocketAddr>().map_err(|e| e.to_string())?;

        Ok(Identifier {
            pubkey_hash,
            id,
            address,
        })
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id_str = match self.id {
            Some(id) => id.to_string(),
            None => "*".to_string(),
        };
        write!(f, "{}:{}@{}", self.pubkey_hash, id_str, self.address)
    }
}
