use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub type PubkHash = String;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identifier {
    pub pubkey_hash: PubkHash,
    pub id: Option<u8>, // For internal services.
                        //`None` represents a wildcard '*'
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.id {
            Some(id) => write!(f, "{}:{}", self.pubkey_hash, id),
            None => write!(f, "{}:*", self.pubkey_hash),
        }
    }
}

impl From<(String, Option<u8>)> for Identifier {
    fn from(tuple: (String, Option<u8>)) -> Self {
        Identifier {
            pubkey_hash: tuple.0,
            id: tuple.1,
        }
    }
}

impl FromStr for Identifier {
    type Err = String;

    /// Parse format: "pubkey_hash:id" where `id` may be a number or '*'
    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err("Identifier must be in format 'name:id'".to_string());
        }
        let pubkey_hash = parts[0].to_string();
        let id = if parts[1] == "*" {
            None
        } else {
            Some(parts[1].parse::<u8>().map_err(|e| e.to_string())?)
        };
        Ok(Identifier { pubkey_hash, id })
    }
}
