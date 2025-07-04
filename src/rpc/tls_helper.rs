use std::sync::Mutex;
use std::{io, sync::Arc};

use pem::Pem;
use rcgen::{Certificate, CertificateParams, DnType};
use ring::digest::{digest, SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DistinguishedName, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use tracing::info;
use x509_parser::der_parser::der::parse_der_sequence;
use x509_parser::parse_x509_certificate;

use crate::allow_list::AllowList;

#[derive(Debug, Clone)]
pub struct Cert {
    name: String,
    key_pem: String,
    cert_pem: String,
    spki_der: Vec<u8>,
}

impl Cert {
    pub fn new(name: &str) -> Result<Self, anyhow::Error> {
        let cert = Self::create_cert(name)?;
        let (key_pem, cert_pem, spki_der) = Self::get_vars(&cert)?;
        info!("Created new certificate for {}", name);
        Ok(Self {
            name: name.to_string(),
            key_pem,
            cert_pem,
            spki_der,
        })
    }

    pub fn get_private_key(&self) -> Result<PrivateKeyDer<'static>, anyhow::Error> {
        let block = pem::parse(self.key_pem.clone())?;
        let key = PrivateKeyDer::try_from(block.contents()).map_err(anyhow::Error::msg)?;
        Ok(key.clone_key())
    }

    pub fn get_cert(&self) -> Result<Vec<CertificateDer<'static>>, anyhow::Error> {
        let blocks: Vec<Pem> = pem::parse_many(self.cert_pem.clone())?;

        let cert = blocks
            .into_iter()
            .filter(|block| block.tag() == "CERTIFICATE")
            .map(|block| {
                let der_bytes = block.into_contents();
                CertificateDer::from(der_bytes)
            })
            .collect();

        Ok(cert)
    }

    pub fn get_pubk_hash(&self) -> Result<String, anyhow::Error> {
        let (_, seq) = parse_der_sequence(&self.spki_der)?;
        let mut iter = seq.as_sequence()?.iter();
        let _algorithm = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing algorithm"))?;
        let subject_pubkey = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing subjectPublicKey"))?;
        let bitstring = subject_pubkey.as_bitstring()?;
        let fingerprint = Sha256::digest(bitstring);
        let hexsum = hex::encode(fingerprint);
        Ok(hexsum)
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn from_file(path: &str, name: &str) -> Result<Self, anyhow::Error> {
        let cert_path = format!("{}/{}.pem", path, name);
        let key_path = format!("{}/{}.key", path, name);

        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;

        let cert_blocks = pem::parse_many(&cert_pem)?;
        let first_cert_block = cert_blocks
            .into_iter()
            .find(|b| b.tag() == "CERTIFICATE")
            .ok_or_else(|| {
                anyhow::anyhow!("No certificate block found in PEM file for {}", name)
            })?;

        let cert_der = first_cert_block.contents();
        let (_, parsed) = parse_x509_certificate(cert_der)?;
        let spki_der = parsed.tbs_certificate.subject_pki.raw.to_vec();

        Ok(Self {
            name: name.to_string(),
            key_pem,
            cert_pem,
            spki_der,
        })
    }

    fn create_cert(name: &str) -> Result<Certificate, anyhow::Error> {
        let mut params = CertificateParams::new(vec![]);
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        Ok(Certificate::from_params(params)?)
    }

    fn get_vars(cert: &Certificate) -> Result<(String, String, Vec<u8>), anyhow::Error> {
        let key_pem = cert.serialize_private_key_pem();
        let cert_pem = cert.serialize_pem()?;
        let spki_der = cert.get_key_pair().public_key_der();
        Ok((key_pem, cert_pem, spki_der))
    }
}

#[derive(Debug)]
pub struct ArcAllowList {
    allow_list: Arc<Mutex<AllowList>>,
}

impl ArcAllowList {
    pub fn new(allow_list: Arc<Mutex<AllowList>>) -> Self {
        Self { allow_list }
    }
}

impl ServerCertVerifier for ArcAllowList {
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

        let is_allowed = {
            let guard = self.allow_list.lock().map_err(|e| {
                rustls::Error::General(format!("Failed to lock allow list: {:?}", e))
            })?;
            guard.is_allowed(&fingerprint_hex)
        };

        if is_allowed {
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

impl ClientCertVerifier for ArcAllowList {
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

        let is_allowed = {
            let guard = self.allow_list.lock().map_err(|e| {
                rustls::Error::General(format!("Failed to lock allow list: {:?}", e))
            })?;
            guard.is_allowed(&fingerprint_hex)
        };

        if is_allowed {
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
