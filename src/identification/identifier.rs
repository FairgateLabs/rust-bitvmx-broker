use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::settings::MAX_PUBKEY_HASH_LEN;

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

impl From<(PubkHash, u8)> for Identifier {
    fn from(tuple: (PubkHash, u8)) -> Self {
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

        let pubkey_hash = parts[0].trim().to_string();

        // --- Sanitization checks ---
        if pubkey_hash.is_empty() {
            return Err("pubkey_hash cannot be empty".to_string());
        }
        if pubkey_hash.len() > MAX_PUBKEY_HASH_LEN {
            return Err(format!(
                "pubkey_hash too long (max {} chars)",
                MAX_PUBKEY_HASH_LEN
            ));
        }

        let id = parts[1]
            .trim()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifier_from_str() {
        // Valid input
        let id: Identifier = "abc123:42".parse().unwrap();
        assert_eq!(id.pubkey_hash, "abc123");
        assert_eq!(id.id, 42);
        assert_eq!(id.to_string(), "abc123:42");

        // Empty pubkey
        assert!(":10".parse::<Identifier>().is_err());

        // Too long pubkey
        let long_key = "x".repeat(MAX_PUBKEY_HASH_LEN + 1);
        let input = format!("{}:1", long_key);
        assert!(input.parse::<Identifier>().is_err());

        // Missing colon
        assert!("abc123".parse::<Identifier>().is_err());

        // Too many colons
        assert!("a:b:c".parse::<Identifier>().is_err());

        // Invalid id
        assert!("abc:notanumber".parse::<Identifier>().is_err());

        // Id out of range (u8 max is 255)
        assert!("abc:999".parse::<Identifier>().is_err());
    }
}
