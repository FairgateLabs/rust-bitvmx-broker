use crate::rpc::errors::Severity;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentificationError {
    #[error("IO error")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse YAML: {0}")]
    YamlParseError(#[from] serde_yaml::Error),

    #[error("Failed to parse JSON: {0}")]
    JsonParseError(#[from] serde_json::Error),

    #[error("Invalid routing line: {0}")]
    InvalidRoutingLine(String),

    #[error("Routes can only be edited while the routing table is in table mode")]
    NotInTableMode,

    //std::string::String
    #[error("Failed to parse identifier: {0}")]
    InvalidIdentifier(String),
}

impl IdentificationError {
    pub fn severity(&self) -> Severity {
        match self {
            // Allow lists and routing tables are read at startup, so anything wrong with one is a configuration problem.
            IdentificationError::IoError(_)
            | IdentificationError::YamlParseError(_)
            | IdentificationError::JsonParseError(_)
            | IdentificationError::InvalidRoutingLine(_)
            | IdentificationError::InvalidIdentifier(_) => Severity::Fatal,
            // Editing routes while the table is in AllowAll or OnlyTo mode.
            IdentificationError::NotInTableMode => Severity::Programming,
        }
    }
}
