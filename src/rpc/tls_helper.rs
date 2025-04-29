use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;

use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::{BufReader, Result as IoResult};

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
