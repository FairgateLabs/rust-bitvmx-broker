use std::{collections::HashMap, fs};

#[derive(Debug)]
pub struct AllowList {
    allow_list: HashMap<String, String>,
}

impl AllowList {
    pub fn new() -> Self {
        Self {
            allow_list: HashMap::new(),
        }
    }

    pub fn from_file(allow_list_path: String) -> Result<Self, anyhow::Error> {
        let content = fs::read_to_string(allow_list_path)?;
        let allow_list: HashMap<String, String> = serde_yaml::from_str(&content)?;
        Ok(Self { allow_list })
    }

    pub fn is_allowed(&self, key: &str) -> bool {
        self.allow_list.contains_key(key)
    }

    pub fn add(&mut self, key: String, value: String) {
        self.allow_list.insert(key, value);
    }

    pub fn remove(&mut self, key: &str) {
        self.allow_list.remove(key);
    }

    pub fn remove_by_value(&mut self, value: &str) -> Option<(String, String)> {
        if let Some(key) = self
            .allow_list
            .iter()
            .find(|(_, v)| v == &&value)
            .map(|(k, _)| k.clone())
        {
            if let Some(value) = self.allow_list.remove(&key) {
                Some((key, value))
            } else {
                None
            }
        } else {
            None
        }
    }
}
