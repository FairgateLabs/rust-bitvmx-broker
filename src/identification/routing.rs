use crate::identification::identifier::Identifier;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    collections::{HashMap, HashSet},
    fs,
    str::FromStr,
    sync::{Arc, Mutex},
};

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct RoutingTable {
    routes: HashMap<Identifier, HashSet<Identifier>>, // Map from source Identifier to a set of allowed destination Identifiers
    allow_all: bool,                                  // If true, all Identifiers are allowed
}

impl RoutingTable {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            routes: HashMap::new(),
            allow_all: false, // Default to not allowing all
        }))
    }

    /// Load routing table from YAML file
    pub fn load_from_file(path: &str) -> Result<Arc<Mutex<Self>>, anyhow::Error> {
        let content = fs::read_to_string(path)?;

        if content == "allow_all" {
            return Ok(Arc::new(Mutex::new(Self {
                routes: HashMap::new(),
                allow_all: true,
            })));
        }

        let lines: Vec<String> = serde_yaml::from_str(&content)?;

        let mut routes: HashMap<Identifier, HashSet<Identifier>> = HashMap::new();

        for line in lines {
            let parts: Vec<&str> = line.split(" --> ").collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid routing line: {}", line));
            }

            let from = Identifier::from_str(parts[0].trim()).map_err(anyhow::Error::msg)?;

            // Deserialize the right-hand side using JSON
            let to_list: Vec<String> = serde_json::from_str(parts[1].trim())?;
            let to_set: HashSet<Identifier> = to_list
                .into_iter()
                .map(|s| Identifier::from_str(&s).map_err(anyhow::Error::msg))
                .collect::<Result<_, _>>()?;

            routes.insert(from, to_set);
        }

        Ok(Arc::new(Mutex::new(Self {
            routes,
            allow_all: false,
        })))
    }

    /// Save routing table to YAML file
    pub fn save_to_file(&self, path: &str) -> Result<(), anyhow::Error> {
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
    pub fn add_route(&mut self, from: Identifier, to: Identifier) {
        self.routes
            .entry(from)
            .or_insert_with(HashSet::new)
            .insert(to);
    }

    pub fn add_routes(&mut self, from: Identifier, tos: Vec<Identifier>) {
        let set = self.routes.entry(from).or_insert_with(HashSet::new);
        for to in tos {
            set.insert(to);
        }
    }

    /// Remove a specific route
    pub fn remove_route(&mut self, from: &Identifier, to: &Identifier) {
        if let Some(set) = self.routes.get_mut(from) {
            set.remove(to);
            if set.is_empty() {
                self.routes.remove(from);
            }
        }
    }

    /// Remove all routes from a source Identifier
    pub fn remove_all_from(&mut self, from: &Identifier) {
        self.routes.remove(from);
    }

    /// Remove all routes to a destination Identifier
    pub fn remove_all_to(&mut self, to: &Identifier) {
        for set in self.routes.values_mut() {
            set.remove(to);
        }
    }

    /// Check if `from` is allowed to talk to `to`
    pub fn can_route(&self, from: &Identifier, to: &Identifier) -> bool {
        if self.allow_all {
            return true;
        }

        self.routes.iter().any(|(from_rule, to_set)| {
            Self::id_match(from_rule, from)
                && to_set.iter().any(|to_rule| Self::id_match(to_rule, to))
        })
    }

    /// Match `rule` identifier against `actual`, considering `None` (wildcard)
    fn id_match(rule: &Identifier, actual: &Identifier) -> bool {
        rule.pubkey_hash == actual.pubkey_hash && (rule.id.is_none() || rule.id == actual.id)
    }

    pub fn allow_all(&mut self) {
        self.allow_all = true;
    }
}
