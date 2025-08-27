use crate::identification::allow_list::AllowList;
use crate::rpc::errors::BrokerError;
use pem::Pem;
use rcgen::{Certificate, CertificateParams, KeyPair};
use ring::digest::{digest, SHA256};
use rsa::pkcs8::EncodePrivateKey;
use rsa::rand_core::{CryptoRng, RngCore};
use rsa::RsaPrivateKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DistinguishedName, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Once;
use std::{
    io,
    sync::{Arc, Mutex},
};
use tracing::info;
use x509_parser::{der_parser::der::parse_der_sequence, parse_x509_certificate};

#[derive(Debug, Clone)]
pub struct Cert {
    key_pem: String,
    cert_pem: String,
    spki_der: Vec<u8>,
}

impl Cert {
    pub fn new() -> Result<Self, BrokerError> {
        let cert = Self::create_cert(None)?;
        let (key_pem, cert_pem, spki_der) = Self::get_vars(&cert)?;
        info!("Created new certificate");
        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
        })
    }
    /// privk is a hex string in PEM format.
    pub fn new_with_privk(privk: &str) -> Result<Self, BrokerError> {
        let cert = Self::create_cert(Some(privk))?;
        let (key_pem, cert_pem, spki_der) = Self::get_vars(&cert)?;
        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
        })
    }

    pub fn from_key_file(key_path: &str) -> Result<Self, BrokerError> {
        let key_pem = std::fs::read_to_string(key_path)?;
        let cert = Self::create_cert(Some(&key_pem))?;
        let (generated_key_pem, cert_pem, spki_der) = Self::get_vars(&cert)?;
        Ok(Self {
            key_pem: generated_key_pem,
            cert_pem,
            spki_der,
        })
    }

    pub fn from_file(path: &str, name: &str) -> Result<Self, BrokerError> {
        let cert_path = format!("{path}/{name}.pem");
        let key_path = format!("{path}/{name}.key");
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
        let (_, parsed) =
            parse_x509_certificate(cert_der).map_err(|e| BrokerError::X509ParseError(e.into()))?;
        let spki_der = parsed.tbs_certificate.subject_pki.raw.to_vec();

        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
        })
    }

    pub fn get_private_key(&self) -> Result<PrivateKeyDer<'static>, BrokerError> {
        let block = pem::parse(self.key_pem.clone())?;
        let key = PrivateKeyDer::try_from(block.contents())
            .map_err(|e| anyhow::anyhow!("PrivateKeyDer conversion failed: {e}"))?;
        Ok(key.clone_key())
    }
    pub fn get_cert(&self) -> Result<Vec<CertificateDer<'static>>, BrokerError> {
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
    // SPKI format:
    // SEQUENCE {
    //   AlgorithmIdentifier (rsaEncryption)
    //   BIT STRING (the RSAPublicKey)
    // }
    // This function extracts the SPKI bit string and computes its SHA256 hash.
    pub fn _get_bitstring_pubk_hash(&self) -> Result<String, BrokerError> {
        let (_, seq) = parse_der_sequence(&self.spki_der)
            .map_err(|e| BrokerError::X509ParseError(e.into()))?;
        let mut iter = seq
            .as_sequence()
            .map_err(|e| BrokerError::X509ParseError(e.into()))?
            .iter();
        let _algorithm = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing algorithm"))?;
        let subject_pubkey = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing subjectPublicKey"))?;
        let bitstring = subject_pubkey
            .as_bitstring()
            .map_err(|e| BrokerError::X509ParseError(e.into()))?;
        let fingerprint = Sha256::digest(bitstring);
        let hexsum = hex::encode(fingerprint);
        Ok(hexsum)
    }
    pub fn get_pubk_hash(&self) -> Result<String, BrokerError> {
        let _pubk_hexstring = hex::encode(&self.spki_der);
        let fingerprint = Sha256::digest(&self.spki_der);
        let hexsum = hex::encode(fingerprint);
        Ok(hexsum)
    }

    fn create_cert(privk: Option<&str>) -> Result<Certificate, BrokerError> {
        let mut params = CertificateParams::default();

        if let Some(privk_str) = privk {
            let keypair = KeyPair::from_pem(privk_str)?;
            params.key_pair = Some(keypair);
            params.alg = &rcgen::PKCS_RSA_SHA256;
        }

        Ok(Certificate::from_params(params)?)
    }
    fn get_vars(cert: &Certificate) -> Result<(String, String, Vec<u8>), BrokerError> {
        let key_pem = cert.serialize_private_key_pem();
        let cert_pem = cert.serialize_pem()?;
        let spki_der = cert.get_key_pair().public_key_der();
        Ok((key_pem, cert_pem, spki_der))
    }

    fn generate_private_key<R: RngCore + CryptoRng>(
        rng: &mut R,
        bits: usize,
    ) -> Result<String, BrokerError> {
        let private_key = RsaPrivateKey::new(rng, bits)?;
        let pem = private_key.to_pkcs8_pem(Default::default())?.to_string();
        Ok(pem)
    }

    pub fn generate_key_file<R: RngCore + CryptoRng>(
        path: &str,
        name: &str,
        rng: &mut R,
        bits: usize,
    ) -> Result<(), BrokerError> {
        let key = Self::generate_private_key(rng, bits)?;
        std::fs::create_dir_all(path)?;
        let key_path = format!("{path}/{name}.key");
        std::fs::write(key_path, key)?;
        info!("Private key saved to {path}/{name}.key");
        Ok(())
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

pub fn get_fingerprint_hex(cert: &CertificateDer<'_>) -> Result<String, BrokerError> {
    // Parse cert
    let (_, parsed_cert) = parse_x509_certificate(cert.as_ref())
        .map_err(|e| rustls::Error::General(format!("Cert parse error: {e:?}")))?;
    // Extract SPKI
    let spki = parsed_cert.tbs_certificate.subject_pki.raw;
    // Hash SPKI
    let fingerprint = digest(&SHA256, spki);
    Ok(hex::encode(fingerprint.as_ref()))
}

pub fn get_pubk_hash_from_privk(privk: &str) -> Result<String, BrokerError> {
    let cert = Cert::new_with_privk(privk)?;
    let fingerprint = cert.get_pubk_hash()?;
    Ok(fingerprint)
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
        let fingerprint_hex = get_fingerprint_hex(cert)
            .map_err(|e| rustls::Error::General(format!("Failed to get fingerprint: {e:?}")))?;
        let is_allowed = {
            let guard = self
                .allow_list
                .lock()
                .map_err(|e| rustls::Error::General(format!("Failed to lock allow list: {e:?}")))?;
            guard.is_allowed_by_fingerprint(&fingerprint_hex)
        };
        if is_allowed {
            info!("✅ Server authorized (fingerprint: {fingerprint_hex})");
            Ok(ServerCertVerified::assertion())
        } else {
            info!("❌ Unauthorized server (fingerprint: {fingerprint_hex})");
            let err = io::Error::new(
                io::ErrorKind::Other,
                format!("Unauthorized fingerprint: {fingerprint_hex}"),
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
        let fingerprint_hex = get_fingerprint_hex(cert)
            .map_err(|e| rustls::Error::General(format!("Failed to get fingerprint: {e:?}")))?;
        let is_allowed = {
            let guard = self
                .allow_list
                .lock()
                .map_err(|e| rustls::Error::General(format!("Failed to lock allow list: {e:?}")))?;
            guard.is_allowed_by_fingerprint(&fingerprint_hex)
        };
        if is_allowed {
            info!("✅ Client authorized (fingerprint: {fingerprint_hex})");
            Ok(ClientCertVerified::assertion())
        } else {
            info!("❌ Unauthorized client (fingerprint: {fingerprint_hex})");
            let err = io::Error::new(
                io::ErrorKind::Other,
                format!("Unauthorized fingerprint: {fingerprint_hex}"),
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

static INIT_TLS: Once = Once::new();

pub fn init_tls() {
    INIT_TLS.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
