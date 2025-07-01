use ring::digest::{digest, SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, Error as RustlsError};
use rustls::{DistinguishedName, RootCertStore, SignatureScheme};
use std::{io, sync::Arc};
use tracing::info;
use x509_parser::parse_x509_certificate;

use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

type Allowlist = HashMap<String, String>;

#[derive(Debug, Clone)]
pub struct CertFiles {
    // (allow_list.yaml, my_cert.pem, my_key.key)
    allow_list: String,
    cert: String,
    key: String,
}

impl CertFiles {
    pub fn new(allow_list: String, cert: String, key: String) -> Self {
        Self {
            allow_list,
            cert,
            key,
        }
    }

    pub fn get_allow_list(&self) -> &str {
        &self.allow_list
    }

    pub fn load_certs(&self) -> Result<Vec<CertificateDer<'static>>, anyhow::Error> {
        let file = File::open(self.cert.clone())?;
        let mut reader = BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
        Ok(certs)
    }

    pub fn load_private_key(&self) -> Result<PrivateKeyDer<'static>, anyhow::Error> {
        let file = File::open(self.key.clone())?;
        let mut reader = BufReader::new(file);
        let keys = rustls_pemfile::private_key(&mut reader)?
            .ok_or_else(|| anyhow::anyhow!("No private key found"))?;
        Ok(keys)
    }

    pub fn _load_root_store(cert_path: &str) -> Result<RootCertStore, anyhow::Error> {
        let mut root_store = RootCertStore::empty();
        let cert_file = File::open(cert_path)?;
        let mut reader = BufReader::new(cert_file);
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
        for cert in certs {
            root_store.add(cert)?;
        }
        Ok(root_store)
    }

    pub fn load_allowlist_from_yaml(&self) -> Result<Allowlist, anyhow::Error> {
        let content = fs::read_to_string(self.allow_list.clone())?;
        let allowlist: Allowlist = serde_yaml::from_str(&content)?;
        Ok(allowlist)
    }

    fn _get_allowlist_path() -> Result<String, anyhow::Error> {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let binding = base.join("certs/allowlist.yaml");
        let path = binding
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid wihtelist path"))?;
        Ok(path.to_string())
    }
}

#[derive(Debug)]
pub struct AllowList {
    allow_list: HashMap<String, String>,
}

impl AllowList {
    pub fn new(allow_list: HashMap<String, String>) -> Self {
        Self { allow_list }
    }
}

impl ServerCertVerifier for AllowList {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Parse cert
        let (_, parsed_cert) = parse_x509_certificate(cert.as_ref())
            .map_err(|e| rustls::Error::General(format!("Cert parse error: {:?}", e)))?;

        // Extract SPKI
        let spki = parsed_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;

        // Hash SPKI
        let fingerprint = digest(&SHA256, &spki);
        let fingerprint_hex = hex::encode(fingerprint.as_ref());

        if self.allow_list.contains_key(&fingerprint_hex) {
            info!("✅ Server authorized (fingerprint: {})", fingerprint_hex);
            Ok(ServerCertVerified::assertion())
        } else {
            info!("❌ Unauthorized server (fingerprint: {})", fingerprint_hex);
            let err = io::Error::new(
                io::ErrorKind::Other,
                format!("Unauthorized fingerprint: {}", fingerprint_hex),
            );
            Err(RustlsError::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(err)),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

impl ClientCertVerifier for AllowList {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Parse cert
        let (_, parsed_cert) = parse_x509_certificate(cert.as_ref())
            .map_err(|e| rustls::Error::General(format!("Cert parse error: {:?}", e)))?;

        // Extract SPKI
        let spki = parsed_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;

        // Compute SHA256 fingerprint
        let fingerprint = digest(&SHA256, &spki);
        let fingerprint_hex = hex::encode(fingerprint);

        // Hash SPKI
        if self.allow_list.contains_key(&fingerprint_hex) {
            info!("✅ Client authorized (fingerprint: {})", fingerprint_hex);
            Ok(ClientCertVerified::assertion())
        } else {
            info!("❌ Unauthorized client (fingerprint: {})", fingerprint_hex);
            let err = io::Error::new(
                io::ErrorKind::Other,
                format!("Unauthorized fingerprint: {}", fingerprint_hex),
            );
            Err(RustlsError::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(err)),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}
