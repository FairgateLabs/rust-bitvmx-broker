use crate::{
    identification::{
        errors::IdentificationError,
        identifier::{Identifier, PubkHash},
    },
    settings::MAX_PUBKEY_HASH_LEN,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{HashMap, HashSet},
    fs,
    str::FromStr,
    sync::{Arc, Mutex},
};

// Markers used by the file format to store a mode that is not an ordinary route table.
const ALLOW_ALL_LINE: &str = "allow_all";
const ONLY_TO_PREFIX: &str = "only_to ";

pub enum WildCard {
    No,
    From,
    To,
    Both,
}

/// How can_route decides. Table consults the routes it carries, AllowAll lets everything through,
/// and OnlyTo accepts a message solely by its destination, whoever the sender is.
#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub enum RoutingMode {
    Table(HashMap<RouteIdentifier, HashSet<RouteIdentifier>>), // Map from source Identifier to a set of allowed destination Identifiers
    AllowAll,
    OnlyTo(RouteIdentifier),
}

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct RouteIdentifier {
    pub pubkey_hash: PubkHash,
    pub id: Option<u8>,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct RoutingTable {
    mode: RoutingMode, // Which of the three decision rules can_route applies
}

impl RoutingTable {
    pub fn new() -> Arc<Mutex<Self>> {
        // Default to allowing only what the table says
        Self::with_mode(RoutingMode::Table(HashMap::new()))
    }

    /// Accept everything, whoever sends and wherever it is addressed.
    /// Any routes the table was carrying are dropped and lost along with the Table mode that held them.
    pub fn allow_all(&mut self) {
        self.mode = RoutingMode::AllowAll;
    }

    /// Accept only messages addressed to this identifier, whoever the sender is.
    /// Any routes the table was carrying are dropped and lost along with the Table mode that held them.
    pub fn allow_only_to(&mut self, dest: &Identifier) {
        self.mode = RoutingMode::OnlyTo(RouteIdentifier::from(dest));
    }

    /// Decide by the route table. Routes already held are kept, so this is not a reset.
    pub fn allow_table(&mut self) {
        if !matches!(self.mode, RoutingMode::Table(_)) {
            self.mode = RoutingMode::Table(HashMap::new());
        }
    }

    /// Load routing table from YAML file
    pub fn from_file(path: &str) -> Result<Arc<Mutex<Self>>, IdentificationError> {
        let content = fs::read_to_string(path)?;
        let trimmed = content.trim();

        if trimmed == ALLOW_ALL_LINE {
            return Ok(Self::with_mode(RoutingMode::AllowAll));
        }

        if let Some(dest) = trimmed.strip_prefix(ONLY_TO_PREFIX) {
            let dest = RouteIdentifier::from_str(dest.trim())
                .map_err(|_| IdentificationError::InvalidRoutingLine(trimmed.to_string()))?;
            return Ok(Self::with_mode(RoutingMode::OnlyTo(dest)));
        }

        Self::parse_yaml(&content)
    }

    /// Save routing table to YAML file
    pub fn save_to_file(&self, path: &str) -> Result<(), IdentificationError> {
        match &self.mode {
            RoutingMode::AllowAll => fs::write(path, ALLOW_ALL_LINE)?,
            RoutingMode::OnlyTo(dest) => fs::write(path, format!("{ONLY_TO_PREFIX}{dest}"))?,
            RoutingMode::Table(routes) => fs::write(path, serde_yaml::to_string(routes)?)?,
        }
        Ok(())
    }

    /// Add a route from `from` to `to`
    pub fn add_route(
        &mut self,
        from: Identifier,
        to: Identifier,
        wild_card: WildCard,
    ) -> Result<(), IdentificationError> {
        let (from_rule, to_rule) = Self::rules(&from, &to, wild_card);
        self.routes_mut()?
            .entry(from_rule)
            .or_insert_with(HashSet::new)
            .insert(to_rule);
        Ok(())
    }

    pub fn add_routes(
        &mut self,
        from: Identifier,
        tos: Vec<Identifier>,
    ) -> Result<(), IdentificationError> {
        let set = self
            .routes_mut()?
            .entry(RouteIdentifier::from(&from))
            .or_insert_with(HashSet::new);
        for to in tos {
            set.insert(RouteIdentifier::from(&to));
        }
        Ok(())
    }

    /// Remove a specific route
    pub fn remove_route(
        &mut self,
        from: &Identifier,
        to: &Identifier,
    ) -> Result<(), IdentificationError> {
        self.remove_route_with_wildcard(from, to, WildCard::No)
    }

    /// Remove a route from `from` to `to` with support for wildcards
    pub fn remove_route_with_wildcard(
        &mut self,
        from: &Identifier,
        to: &Identifier,
        wild_card: WildCard,
    ) -> Result<(), IdentificationError> {
        let (from_rule, to_rule) = Self::rules(from, to, wild_card);
        let routes = self.routes_mut()?;

        if let Some(set) = routes.get_mut(&from_rule) {
            set.remove(&to_rule);
            if set.is_empty() {
                routes.remove(&from_rule);
            }
        }
        Ok(())
    }

    /// Remove all routes from a source Identifier
    pub fn remove_all_from(&mut self, from: &Identifier) -> Result<(), IdentificationError> {
        let from_rule = RouteIdentifier::from(from);
        self.routes_mut()?.remove(&from_rule);
        Ok(())
    }

    /// Remove all routes to a destination Identifier
    pub fn remove_all_to(&mut self, to: &Identifier) -> Result<(), IdentificationError> {
        let to_rule = RouteIdentifier::from(to);
        let routes = self.routes_mut()?;
        for set in routes.values_mut() {
            set.retain(|route| route != &to_rule);
        }
        // A source left with no destinations is dropped.
        routes.retain(|_, set| !set.is_empty());
        Ok(())
    }

    /// Check if `from` is allowed to talk to `to`
    pub fn can_route(&self, from: &Identifier, to: &Identifier) -> bool {
        match &self.mode {
            RoutingMode::AllowAll => true,
            RoutingMode::OnlyTo(dest) => Self::id_match(dest, &RouteIdentifier::from(to)),
            RoutingMode::Table(routes) => routes.iter().any(|(from_rule, to_set)| {
                Self::id_match(from_rule, &RouteIdentifier::from(from))
                    && to_set
                        .iter()
                        .any(|to_rule| Self::id_match(to_rule, &RouteIdentifier::from(to)))
            }),
        }
    }

    // Routes only decide anything in table mode.
    fn routes_mut(
        &mut self,
    ) -> Result<&mut HashMap<RouteIdentifier, HashSet<RouteIdentifier>>, IdentificationError> {
        match &mut self.mode {
            RoutingMode::Table(routes) => Ok(routes),
            _ => Err(IdentificationError::NotInTableMode),
        }
    }

    // The pair of rules a wildcard choice turns a from and a to into.
    fn rules(
        from: &Identifier,
        to: &Identifier,
        wild_card: WildCard,
    ) -> (RouteIdentifier, RouteIdentifier) {
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

        (from_rule, to_rule)
    }

    fn parse_yaml(yaml_str: &str) -> Result<Arc<Mutex<Self>>, IdentificationError> {
        let routes: HashMap<RouteIdentifier, HashSet<RouteIdentifier>> =
            serde_yaml::from_str(yaml_str)?;
        Ok(Self::with_mode(RoutingMode::Table(routes)))
    }

    /// Match `rule` identifier against `actual`, considering `None` (wildcard)
    fn id_match(rule: &RouteIdentifier, actual: &RouteIdentifier) -> bool {
        rule.pubkey_hash == actual.pubkey_hash && (rule.id.is_none() || rule.id == actual.id)
    }

    fn with_mode(mode: RoutingMode) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self { mode }))
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

impl std::fmt::Display for RouteIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.id {
            Some(id) => write!(f, "{}:{}", self.pubkey_hash, id),
            None => write!(f, "{}:~", self.pubkey_hash), // Use '~' to denote wildcard
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
                .map_err(|_| "Invalid id: must be 0–255 or '~'".to_string())?;
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

        // Test TryFrom<String>
        assert_eq!(RouteIdentifier::try_from("abc:1".to_string()).unwrap(), ri);
        assert_eq!(RouteIdentifier::try_from("xyz:~".to_string()).unwrap(), ri2);
        assert!(RouteIdentifier::try_from("invalidformat".to_string()).is_err());
    }

    #[test]
    fn add_and_can_route_basic() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();

        let a = Identifier::new("a".to_string(), 1);
        let b = Identifier::new("b".to_string(), 2);

        rt.add_route(a.clone(), b.clone(), WildCard::No).unwrap();
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
        rt.add_route(a1.clone(), b1.clone(), WildCard::From)
            .unwrap();
        assert!(rt.can_route(&a2, &b1));

        // wildcard on "to"
        rt.add_route(a1.clone(), b1.clone(), WildCard::To).unwrap();
        assert!(rt.can_route(&a1, &b2));

        // wildcard both
        rt.add_route(a1.clone(), b1.clone(), WildCard::Both)
            .unwrap();
        assert!(rt.can_route(&a2, &b3));
    }

    #[test]
    fn remove_routes() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();

        let a = &Identifier::new("a".to_string(), 1);
        let b = &Identifier::new("b".to_string(), 1);

        rt.add_route(a.clone(), b.clone(), WildCard::No).unwrap();
        assert!(rt.can_route(&a, &b));

        // remove normal
        rt.remove_route(&a, &b).unwrap();
        assert!(!rt.can_route(&a, &b));

        // re-add
        rt.add_route(a.clone(), b.clone(), WildCard::No).unwrap();

        // remove with wildcard
        rt.remove_route_with_wildcard(&a, &b, WildCard::No).unwrap();
        assert!(!rt.can_route(&a, &b));
    }

    #[test]
    fn remove_all() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();
        let a = &Identifier::new("a".to_string(), 1);
        let b1 = &Identifier::new("b".to_string(), 1);
        let b2 = &Identifier::new("b".to_string(), 2);

        rt.add_route(a.clone(), b1.clone(), WildCard::No).unwrap();
        rt.add_route(a.clone(), b2.clone(), WildCard::No).unwrap();

        assert!(rt.can_route(&a, &b1));
        assert!(rt.can_route(&a, &b2));

        rt.remove_all_from(&a).unwrap();
        assert!(!rt.can_route(&a, &b1));
        assert!(!rt.can_route(&a, &b2));

        rt.add_route(a.clone(), b1.clone(), WildCard::No).unwrap();
        rt.add_route(a.clone(), b2.clone(), WildCard::No).unwrap();
        rt.remove_all_to(&b1).unwrap();
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
        rt.add_route(a.clone(), b.clone(), WildCard::No).unwrap();

        rt.save_to_file(file_path.to_str().unwrap()).unwrap();

        let loaded = RoutingTable::from_file(file_path.to_str().unwrap()).unwrap();
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

        let loaded = RoutingTable::from_file(file_path.to_str().unwrap()).unwrap();
        let loaded = loaded.lock().unwrap();
        assert_eq!(loaded.mode, RoutingMode::AllowAll);
    }

    #[test]
    fn allow_only_to_exact_id() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();

        let me = &Identifier::new("me".to_string(), 0);
        rt.allow_only_to(me);

        let sender = &Identifier::new("someone".to_string(), 7);
        assert!(rt.can_route(&sender, &me));

        // Same hash but a different sub id is an address this broker never reads.
        assert!(!rt.can_route(&sender, &Identifier::new("me".to_string(), 77)));

        // Another hash altogether.
        assert!(!rt.can_route(&sender, &Identifier::new("other".to_string(), 0)));
    }

    // There is no method that builds a hash wide OnlyTo, but a file may still ask for one.
    #[test]
    fn load_only_to_whole_hash_from_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("routes.yaml");
        fs::write(&file_path, "only_to me:~").unwrap();

        let rt = RoutingTable::from_file(file_path.to_str().unwrap()).unwrap();
        let rt = rt.lock().unwrap();

        let sender = &Identifier::new("someone".to_string(), 7);
        assert!(rt.can_route(&sender, &Identifier::new("me".to_string(), 0)));
        assert!(rt.can_route(&sender, &Identifier::new("me".to_string(), 77)));
        assert!(!rt.can_route(&sender, &Identifier::new("other".to_string(), 0)));
    }

    #[test]
    fn allow_only_to_ignores_the_sender() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();

        let me = &Identifier::new("me".to_string(), 0);
        rt.allow_only_to(me);

        // Any sender is accepted, the destination is the only thing that decides.
        for hash in ["a", "b", "c"] {
            assert!(rt.can_route(&Identifier::new(hash.to_string(), 3), &me));
        }
    }

    #[test]
    fn save_and_load_only_to() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("only_to.yaml");

        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();
        rt.allow_only_to(&Identifier::new("me".to_string(), 4));
        rt.save_to_file(file_path.to_str().unwrap()).unwrap();

        let loaded = RoutingTable::from_file(file_path.to_str().unwrap()).unwrap();
        let loaded = loaded.lock().unwrap();
        assert_eq!(*loaded, *rt);
    }

    #[test]
    fn routes_can_only_be_edited_in_table_mode() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();

        let a = Identifier::new("a".to_string(), 1);
        let b = Identifier::new("b".to_string(), 1);

        rt.allow_all();
        assert!(matches!(
            rt.add_route(a.clone(), b.clone(), WildCard::No),
            Err(IdentificationError::NotInTableMode)
        ));
        assert!(matches!(
            rt.add_routes(a.clone(), vec![b.clone()]),
            Err(IdentificationError::NotInTableMode)
        ));
        assert!(matches!(
            rt.remove_route(&a, &b),
            Err(IdentificationError::NotInTableMode)
        ));
        assert!(matches!(
            rt.remove_all_from(&a),
            Err(IdentificationError::NotInTableMode)
        ));
        assert!(matches!(
            rt.remove_all_to(&b),
            Err(IdentificationError::NotInTableMode)
        ));

        rt.allow_only_to(&b);
        assert!(matches!(
            rt.add_route(a.clone(), b.clone(), WildCard::No),
            Err(IdentificationError::NotInTableMode)
        ));

        // Back in table mode the same edit goes through.
        rt.allow_table();
        rt.add_route(a.clone(), b.clone(), WildCard::No).unwrap();
        assert!(rt.can_route(&a, &b));
    }

    #[test]
    fn allow_table_keeps_the_routes_it_already_has() {
        let rt = RoutingTable::new();
        let mut rt = rt.lock().unwrap();

        let a = Identifier::new("a".to_string(), 1);
        let b = Identifier::new("b".to_string(), 1);
        rt.add_route(a.clone(), b.clone(), WildCard::No).unwrap();

        rt.allow_table(); // Already in table mode, so this is not a reset.
        assert!(rt.can_route(&a, &b));

        // Leaving table mode drops the routes, and coming back starts empty.
        rt.allow_all();
        rt.allow_table();
        assert!(!rt.can_route(&a, &b));
    }

    #[test]
    fn load_malformed_only_to_fails() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("routes.yaml");
        fs::write(&file_path, "only_to not:a:route").unwrap();

        assert!(RoutingTable::from_file(file_path.to_str().unwrap()).is_err());
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
