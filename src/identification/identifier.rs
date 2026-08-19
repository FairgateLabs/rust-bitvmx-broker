use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::settings::MAX_PUBKEY_HASH_LEN;

pub type PubkHash = String;

/// Rejects hashes that would break the storage key layout, where '/' separates the fields and ':'
/// separates a hash from its id. The storages call this before building a key, so a hash that reached
/// them without being parsed cannot place its message inside another destination namespace.
pub fn validate_pubkey_hash(pubkey_hash: &str) -> Result<(), String> {
    if pubkey_hash.is_empty() {
        return Err("pubkey_hash cannot be empty".to_string());
    }
    if pubkey_hash.len() > MAX_PUBKEY_HASH_LEN {
        return Err(format!(
            "pubkey_hash too long (max {} chars)",
            MAX_PUBKEY_HASH_LEN
        ));
    }
    if pubkey_hash.contains('/') || pubkey_hash.contains(':') {
        return Err("pubkey_hash cannot contain '/' or ':'".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identifier {
    pub pubkey_hash: PubkHash,
    pub id: u8,
}

impl Identifier {
    pub fn new(pubkey_hash: PubkHash, id: u8) -> Self {
        Identifier { pubkey_hash, id }
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_pubkey_hash(&self.pubkey_hash)
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
        let id = parts[1]
            .trim()
            .parse::<u8>()
            .map_err(|e| format!("Invalid id: {}", e))?;

        let identifier = Identifier { pubkey_hash, id };
        identifier.validate()?;
        Ok(identifier)
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

    #[test]
    fn test_validate_rejects_key_separators() {
        assert!(Identifier::new("victimhash:0/whatever".to_string(), 5)
            .validate()
            .is_err());
        assert!(Identifier::new("a/b".to_string(), 0).validate().is_err());
        assert!(Identifier::new("abc123".to_string(), 0).validate().is_ok());
    }
}
