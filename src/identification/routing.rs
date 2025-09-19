use crate::identification::{errors::IdentificationError, identifier::Identifier};
use serde::{Deserialize, Serialize};
use serde_json;
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

#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct RouteIdentifier {
    pub pubkey_hash: String,
    pub id: Option<u8>,
}

impl RouteIdentifier {
    pub fn to_string(&self) -> String {
        match self.id {
            Some(id) => format!("{}:{}", self.pubkey_hash, id),
            None => format!("{}:*", self.pubkey_hash),
        }
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

impl FromStr for RouteIdentifier {
    type Err = String;

    /// Parse format: "pubkey_hash:id" or "pubkey_hash:*"
    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(
                "RouteIdentifier must be in format 'pubkey_hash:id' or 'pubkey_hash:*'".to_string(),
            );
        }

        let pubkey_hash = parts[0].to_string();
        let id = if parts[1] == "*" {
            None
        } else {
            Some(
                parts[1]
                    .parse::<u8>()
                    .map_err(|e| format!("Invalid id: {}", e))?,
            )
        };

        Ok(RouteIdentifier { pubkey_hash, id })
    }
}

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
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

        if content == "allow_all" {
            return Ok(Arc::new(Mutex::new(Self {
                routes: HashMap::new(),
                allow_all: true,
            })));
        }

        let lines: Vec<String> = serde_yaml::from_str(&content)?;

        let mut routes: HashMap<RouteIdentifier, HashSet<RouteIdentifier>> = HashMap::new();

        for line in lines {
            let parts: Vec<&str> = line.split(" --> ").collect();
            if parts.len() != 2 {
                return Err(IdentificationError::InvalidRoutingLine(line));
            }

            let from = RouteIdentifier::from_str(parts[0].trim())
                .map_err(|e| IdentificationError::InvalidIdentifier(e))?;

            // Deserialize the right-hand side using JSON
            let to_list: Vec<String> = serde_json::from_str(parts[1].trim())?;
            let to_set: HashSet<RouteIdentifier> = to_list
                .into_iter()
                .map(|s| {
                    RouteIdentifier::from_str(&s)
                        .map_err(|e| IdentificationError::InvalidIdentifier(e))
                })
                .collect::<Result<_, _>>()?;

            routes.insert(from, to_set);
        }

        Ok(Arc::new(Mutex::new(Self {
            routes,
            allow_all: false,
        })))
    }

    /// Save routing table to YAML file
    pub fn save_to_file(&self, path: &str) -> Result<(), IdentificationError> {
        let mut output: Vec<String> = Vec::new();

        for (from, tos) in &self.routes {
            let from_str = from.to_string();
            let mut to_vec: Vec<String> = tos.iter().map(|to| to.to_string()).collect();
            to_vec.sort(); // For consistent ordering
            let line = format!("{from_str} --> {to_vec:?}");
            output.push(line);
        }

        let yaml = serde_yaml::to_string(&output)?;
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
