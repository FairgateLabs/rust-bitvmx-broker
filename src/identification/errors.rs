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

    //std::string::String
    #[error("Failed to parse identifier: {0}")]
    InvalidIdentifier(String),
}
