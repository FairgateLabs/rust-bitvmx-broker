use crate::identification::{
    errors::IdentificationError,
    identifier::{Identifier, PubkHash, MAX_PUBKEY_HASH_LEN},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{HashMap, HashSet},
    fs,
    str::FromStr,
    sync::{Arc, Mutex},
};

pub enum WildCard {
    No,
    From,
    To,
    Both,
}

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct RouteIdentifier {
    pub pubkey_hash: PubkHash,
    pub id: Option<u8>,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct RoutingTable {
    routes: HashMap<RouteIdentifier, HashSet<RouteIdentifier>>, // Map from source Identifier to a set of allowed destination Identifiers
    allow_all: bool, // If true, all Identifiers are allowed
}

impl RoutingTable {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            routes: HashMap::new(),
            allow_all: false, // Default to not allowing all
        }))
    }

    /// Load routing table from YAML file
    pub fn load_from_file(path: &str) -> Result<Arc<Mutex<Self>>, IdentificationError> {
        let content = fs::read_to_string(path)?;

        if content.trim() == "allow_all" {
            return Ok(Arc::new(Mutex::new(Self {
                routes: HashMap::new(),
                allow_all: true,
            })));
        }

        Self::parse_yaml(&content)
    }

    fn parse_yaml(yaml_str: &str) -> Result<Arc<Mutex<Self>>, IdentificationError> {
        let routes: HashMap<RouteIdentifier, HashSet<RouteIdentifier>> =
            serde_yaml::from_str(yaml_str)?;
        Ok(Arc::new(Mutex::new(Self {
            routes,
            allow_all: false,
        })))
    }

    /// Save routing table to YAML file
    pub fn save_to_file(&self, path: &str) -> Result<(), IdentificationError> {
        if self.allow_all {
            fs::write(path, "allow_all")?;
            return Ok(());
        }

        let yaml = serde_yaml::to_string(&self.routes)?;
        fs::write(path, yaml)?;
        Ok(())
    }

    /// Add a route from `from` to `to`
    pub fn add_route(&mut self, from: Identifier, to: Identifier, wild_card: WildCard) {
        let from_rule = match wild_card {
            WildCard::No | WildCard::To => RouteIdentifier::from(&from),
            WildCard::From | WildCard::Both => RouteIdentifier {
                pubkey_hash: from.pubkey_hash.clone(),
                id: None,
            },
        };

        let to_rule = match wild_card {
            WildCard::No | WildCard::From => RouteIdentifier::from(&to),
            WildCard::To | WildCard::Both => RouteIdentifier {
                pubkey_hash: to.pubkey_hash.clone(),
                id: None,
            },
        };

        let set = self.routes.entry(from_rule).or_insert_with(HashSet::new);
        set.insert(to_rule);
    }

    pub fn add_routes(&mut self, from: Identifier, tos: Vec<Identifier>) {
        let set = self
            .routes
            .entry(RouteIdentifier::from(&from))
            .or_insert_with(HashSet::new);
        for to in tos {
            set.insert(RouteIdentifier::from(&to));
        }
    }

    /// Remove a specific route
    pub fn remove_route(&mut self, from: &Identifier, to: &Identifier) {
        let from_rule = RouteIdentifier::from(from);
        let to_rule = RouteIdentifier::from(to);

        if let Some(set) = self.routes.get_mut(&from_rule) {
            set.remove(&to_rule);
            if set.is_empty() {
                self.routes.remove(&from_rule);
            }
        }
    }

    /// Remove a route from `from` to `to` with support for wildcards
    pub fn remove_route_with_wildcard(
        &mut self,
        from: &Identifier,
        to: &Identifier,
        wild_card: WildCard,
    ) {
        let from_rule = match wild_card {
            WildCard::No | WildCard::To => RouteIdentifier::from(from),
            WildCard::From | WildCard::Both => RouteIdentifier {
                pubkey_hash: from.pubkey_hash.clone(),
                id: None,
            },
        };

        let to_rule = match wild_card {
            WildCard::No | WildCard::From => RouteIdentifier::from(to),
            WildCard::To | WildCard::Both => RouteIdentifier {
                pubkey_hash: to.pubkey_hash.clone(),
                id: None,
            },
        };

        if let Some(set) = self.routes.get_mut(&from_rule) {
            set.remove(&to_rule);
            if set.is_empty() {
                self.routes.remove(&from_rule);
            }
        }
    }

    /// Remove all routes from a source Identifier
    pub fn remove_all_from(&mut self, from: &Identifier) {
        let from_rule = RouteIdentifier::from(from);
        self.routes.remove(&from_rule);
    }

    /// Remove all routes to a destination Identifier
    pub fn remove_all_to(&mut self, to: &Identifier) {
        let to_rule = RouteIdentifier::from(to);
        for set in self.routes.values_mut() {
            set.retain(|route| route != &to_rule);
        }
    }

    /// Check if `from` is allowed to talk to `to`
    pub fn can_route(&self, from: &Identifier, to: &Identifier) -> bool {
        if self.allow_all {
            return true;
        }

        self.routes.iter().any(|(from_rule, to_set)| {
            Self::id_match(from_rule, &RouteIdentifier::from(from))
                && to_set
                    .iter()
                    .any(|to_rule| Self::id_match(to_rule, &RouteIdentifier::from(to)))
        })
    }

    /// Match `rule` identifier against `actual`, considering `None` (wildcard)
    fn id_match(rule: &RouteIdentifier, actual: &RouteIdentifier) -> bool {
        rule.pubkey_hash == actual.pubkey_hash && (rule.id.is_none() || rule.id == actual.id)
    }

    pub fn allow_all(&mut self) {
        self.allow_all = true;
    }
}

impl Serialize for RouteIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RouteIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RouteIdentifier::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl From<&Identifier> for RouteIdentifier {
    fn from(id: &Identifier) -> Self {
        RouteIdentifier {
            pubkey_hash: id.pubkey_hash.clone(),
            id: Some(id.id),
        }
    }
}

impl RouteIdentifier {
    pub fn to_string(&self) -> String {
        match self.id {
            Some(id) => format!("{}:{}", self.pubkey_hash, id),
            None => format!("{}:~", self.pubkey_hash), // Use '~' to denote wildcard
        }
    }
}

impl TryFrom<String> for RouteIdentifier {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        RouteIdentifier::from_str(&value)
    }
}

impl FromStr for RouteIdentifier {
    type Err = String;

    /// Parse format: "pubkey_hash:id" or "pubkey_hash:~"
    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 2 {
            return Err(
                "RouteIdentifier must be in format 'pubkey_hash:id' or 'pubkey_hash:~'".to_string(),
            );
        }

        let pubkey_hash = parts[0].to_string();

        // Sanity check: enforce max length
        if pubkey_hash.len() > MAX_PUBKEY_HASH_LEN {
            return Err(format!(
                "pubkey_hash too long (max {} chars)",
                MAX_PUBKEY_HASH_LEN
            ));
        }

        let id = if parts[1] == "~" {
            None
        } else {
            // Sanity check: ensure it's a number in range
            let parsed = parts[1]
                .parse::<u8>()
                .map_err(|_| format!("Invalid id: must be 0–255 or '~'"))?;
            Some(parsed)
        };

        Ok(RouteIdentifier { pubkey_hash, id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn routeidentifier_to_string_and_fromstr() {
        // normal id
        let ri = RouteIdentifier {
            pubkey_hash: "abc".into(),
            id: Some(1),
        };
        assert_eq!(ri.to_string(), "abc:1");
        assert_eq!(RouteIdentifier::from_str("abc:1").unwrap(), ri);

        // wildcard
        let ri2 = RouteIdentifier {
            pubkey_hash: "xyz".into(),
            id: None,
        };
        assert_eq!(ri2.to_string(), "xyz:~");
        assert_eq!(RouteIdentifier::from_str("xyz:~").unwrap(), ri2);

        //wrong format
        assert!(RouteIdentifier::from_str("invalidformat").is_err());
        assert!(RouteIdentifier::from_str("too:many:parts").is_err());
        assert!(RouteIdentifier::from_str("abc:9999").is_err()); // out of u8 range

        let long = "x".repeat(MAX_PUBKEY_HASH_LEN + 1);
        let s = format!("{long}:1");
        assert!(RouteIdentifier::from_str(&s).is_err()); // too long pubkey
    }

    #[test]
    fn add_and_can_route_basic() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();

        let a = Identifier::new("a".to_string(), 1);
        let b = Identifier::new("b".to_string(), 2);

        rt.add_route(a.clone(), b.clone(), WildCard::No);
        assert!(rt.can_route(&a, &b));
        assert!(!rt.can_route(&a, &Identifier::new("b".to_string(), 3)));
    }

    #[test]
    fn add_with_wildcards() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();

        let a1 = &Identifier::new("a".to_string(), 1);
        let a2 = &Identifier::new("a".to_string(), 2);
        let b1 = &Identifier::new("b".to_string(), 1);
        let b2 = &Identifier::new("b".to_string(), 99);
        let b3 = &Identifier::new("b".to_string(), 100);

        // wildcard on "from"
        rt.add_route(a1.clone(), b1.clone(), WildCard::From);
        assert!(rt.can_route(&a2, &b1));

        // wildcard on "to"
        rt.add_route(a1.clone(), b1.clone(), WildCard::To);
        assert!(rt.can_route(&a1, &b2));

        // wildcard both
        rt.add_route(a1.clone(), b1.clone(), WildCard::Both);
        assert!(rt.can_route(&a2, &b3));
    }

    #[test]
    fn remove_routes() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();

        let a = &Identifier::new("a".to_string(), 1);
        let b = &Identifier::new("b".to_string(), 1);

        rt.add_route(a.clone(), b.clone(), WildCard::No);
        assert!(rt.can_route(&a, &b));

        // remove normal
        rt.remove_route(&a, &b);
        assert!(!rt.can_route(&a, &b));

        // re-add
        rt.add_route(a.clone(), b.clone(), WildCard::No);

        // remove with wildcard
        rt.remove_route_with_wildcard(&a, &b, WildCard::No);
        assert!(!rt.can_route(&a, &b));
    }

    #[test]
    fn remove_all() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();
        let a = &Identifier::new("a".to_string(), 1);
        let b1 = &Identifier::new("b".to_string(), 1);
        let b2 = &Identifier::new("b".to_string(), 2);

        rt.add_route(a.clone(), b1.clone(), WildCard::No);
        rt.add_route(a.clone(), b2.clone(), WildCard::No);

        assert!(rt.can_route(&a, &b1));
        assert!(rt.can_route(&a, &b2));

        rt.remove_all_from(&a);
        assert!(!rt.can_route(&a, &b1));
        assert!(!rt.can_route(&a, &b2));

        rt.add_route(a.clone(), b1.clone(), WildCard::No);
        rt.add_route(a.clone(), b2.clone(), WildCard::No);
        rt.remove_all_to(&b1);
        assert!(!rt.can_route(&a, &b1));
        assert!(rt.can_route(&a, &b2));
    }

    #[test]
    fn allow_all_flag() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();
        rt.allow_all();
        let a = &Identifier::new("a".to_string(), 1);
        let b = &Identifier::new("b".to_string(), 2);
        assert!(rt.can_route(&a, &b));
    }

    #[test]
    fn save_and_load_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("routes.yaml");

        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();
        let a = &Identifier::new("a".to_string(), 1);
        let b = &Identifier::new("b".to_string(), 1);
        rt.add_route(a.clone(), b.clone(), WildCard::No);

        rt.save_to_file(file_path.to_str().unwrap()).unwrap();

        let loaded = RoutingTable::load_from_file(file_path.to_str().unwrap()).unwrap();
        let loaded = loaded.lock().unwrap();
        assert!(loaded.can_route(&a, &b));
    }

    #[test]
    fn save_and_load_allow_all() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("routes.yaml");

        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();
        rt.allow_all();
        rt.save_to_file(file_path.to_str().unwrap()).unwrap();

        let loaded = RoutingTable::load_from_file(file_path.to_str().unwrap()).unwrap();
        let loaded = loaded.lock().unwrap();
        assert!(loaded.allow_all);
    }

    #[test]
    fn test_format() {
        let yaml = r#"
        "pubk1:1":
          - "pubk2:1"
          - "pubk3:2"
        "pubk1:~":
          - "pubk4:5"
        "#;

        RoutingTable::parse_yaml(&yaml).expect("Failed to parse routing");
    }
}
