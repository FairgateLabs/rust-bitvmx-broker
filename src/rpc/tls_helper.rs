use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;

use rustls_pemfile::{certs, private_key};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Result as IoResult};
use std::path::PathBuf;

type Whitelist = HashMap<String, String>;

pub fn load_certs(filename: &str) -> Result<Vec<CertificateDer<'static>>, anyhow::Error> {
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

pub fn load_private_key(filename: &str) -> Result<PrivateKeyDer<'static>, anyhow::Error> {
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);
    let keys = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;
    Ok(keys)
}

pub fn load_root_store(cert_path: &str) -> Result<RootCertStore, anyhow::Error> {
    let mut root_store = RootCertStore::empty();
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    for cert in certs {
        root_store.add(cert)?;
    }
    Ok(root_store)
}

pub fn load_whitelist_from_yaml(path: &str) -> Result<Whitelist, anyhow::Error> {
    let content = fs::read_to_string(path)?;
    let whitelist: Whitelist = serde_yaml::from_str(&content)?;
    Ok(whitelist)
}

pub fn get_whitelist_path() -> Result<String, anyhow::Error> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binding = base.join("certs/whitelist.yaml");
    let path = binding
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid wihtelist path"))?;
    Ok(path.to_string())
}
