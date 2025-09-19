use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub type PubkHash = String;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identifier {
    pub pubkey_hash: PubkHash,
    pub id: u8,
}

impl Identifier {
    pub fn new(pubkey_hash: PubkHash, id: u8) -> Self {
        Identifier { pubkey_hash, id }
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
            return Err("Identifier must be in format 'pubkey_hash:id'".to_string());
        }

        let pubkey_hash = parts[0].to_string();
        let id = parts[1]
            .parse::<u8>()
            .map_err(|e| format!("Invalid id: {}", e))?;

        Ok(Identifier { pubkey_hash, id })
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.pubkey_hash, self.id)
    }
}
