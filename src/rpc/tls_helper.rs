use crate::identification::{allow_list::AllowList, identifier::PubkHash};
use crate::rpc::errors::BrokerError;
use crate::settings::CA_KEY;
use pem::Pem;
use rcgen::{Certificate, CertificateParams, KeyPair, SanType};
use ring::digest::{digest, SHA256};
use rsa::{
    pkcs8::EncodePrivateKey,
    rand_core::{CryptoRng, RngCore},
    RsaPrivateKey,
};
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        VerifierBuilderError, WebPkiClientVerifier,
    },
    CertificateError, DistinguishedName, Error as RustlsError, SignatureScheme,
};
use sha2::{Digest, Sha256};
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
    ca_der: Vec<u8>,
    pubk_hash: PubkHash,
}

impl Cert {
    fn pubk_hash_from_der(spki_der: &Vec<u8>) -> Result<PubkHash, BrokerError> {
        let fingerprint = Sha256::digest(spki_der);
        let hexsum = hex::encode(fingerprint);
        Ok(hexsum)
    }

    pub fn new() -> Result<Self, BrokerError> {
        let cert = Self::create_cert(None)?;
        let (key_pem, cert_pem, spki_der, ca_der) = Self::get_vars(&cert, CA_KEY)?;
        let pubk_hash = Self::pubk_hash_from_der(&spki_der)?;
        info!("Created new certificate");
        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
            ca_der,
            pubk_hash,
        })
    }
    /// privk is a hex string in PEM format.
    pub fn new_with_privk(privk: &str) -> Result<Self, BrokerError> {
        let cert = Self::create_cert(Some(privk))?;
        let (key_pem, cert_pem, spki_der, ca_der) = Self::get_vars(&cert, CA_KEY)?;
        let pubk_hash = Self::pubk_hash_from_der(&spki_der)?;
        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
            ca_der,
            pubk_hash,
        })
    }
    pub fn new_with_privk_and_ca(privk: &str, ca_key: &str) -> Result<Self, BrokerError> {
        let cert = Self::create_cert(Some(privk))?;
        let (key_pem, cert_pem, spki_der, ca_der) = Self::get_vars(&cert, ca_key)?;
        let pubk_hash = Self::pubk_hash_from_der(&spki_der)?;
        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
            ca_der,
            pubk_hash,
        })
    }
    pub fn from_key_file(key_path: &str) -> Result<Self, BrokerError> {
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| BrokerError::AboutCertsAllow(e.into()))?;
        Self::new_with_privk(&key_pem)
    }

    pub fn from_file(path: &str, name: &str) -> Result<Self, BrokerError> {
        let cert_path = format!("{path}/{name}.pem");
        let key_path = format!("{path}/{name}.key");
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| BrokerError::AboutCertsAllow(e.into()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| BrokerError::AboutCertsAllow(e.into()))?;

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

        let ca = Self::load_ca(CA_KEY)?;
        let ca_der = ca.serialize_der()?;
        let pubk_hash = Self::pubk_hash_from_der(&spki_der)?;
        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
            ca_der,
            pubk_hash,
        })
    }

    fn create_cert(privk: Option<&str>) -> Result<Certificate, BrokerError> {
        let mut params = CertificateParams::default();

        params.subject_alt_names = vec![
            SanType::DnsName("localhost".into()),
            SanType::IpAddress("127.0.0.1".parse()?),
        ];
        if let Some(privk_str) = privk {
            let keypair = KeyPair::from_pem(privk_str)?;
            params.key_pair = Some(keypair);
            params.alg = &rcgen::PKCS_RSA_SHA256;
        }

        Ok(Certificate::from_params(params)?)
    }
    fn load_ca(ca_key: &str) -> Result<rcgen::Certificate, BrokerError> {
        let key_pair = KeyPair::from_pem(ca_key)?;

        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_pair = Some(key_pair);
        params.alg = &rcgen::PKCS_RSA_SHA256;

        let ca = Certificate::from_params(params)?;
        Ok(ca)
    }
    fn get_vars(
        cert: &Certificate,
        ca_key: &str,
    ) -> Result<(String, String, Vec<u8>, Vec<u8>), BrokerError> {
        let key_pem = cert.serialize_private_key_pem();
        let spki_der = cert.get_key_pair().public_key_der();
        let ca = Self::load_ca(ca_key)?;
        let cert_pem = cert.serialize_pem_with_signer(&ca)?;
        let ca_der = ca.serialize_der()?;
        Ok((key_pem, cert_pem, spki_der, ca_der))
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
        std::fs::create_dir_all(path).map_err(|e| BrokerError::AboutCertsAllow(e.into()))?;
        let key_path = format!("{path}/{name}.key");
        std::fs::write(key_path, key).map_err(|e| BrokerError::AboutCertsAllow(e.into()))?;
        info!("Private key saved to {path}/{name}.key");
        Ok(())
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
    pub fn get_ca_cert_der(
        self,
    ) -> Result<rustls::pki_types::CertificateDer<'static>, BrokerError> {
        Ok(self.ca_der.into())
    }
    pub fn get_pubk_hash(&self) -> Result<PubkHash, BrokerError> {
        Ok(self.pubk_hash.clone())
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
}

#[derive(Debug)]
pub struct AllowListServerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    allow_list: Arc<Mutex<AllowList>>,
}

impl AllowListServerVerifier {
    pub fn new(
        allow_list: Arc<Mutex<AllowList>>,
        roots: Arc<rustls::RootCertStore>,
    ) -> Result<Self, VerifierBuilderError> {
        let inner = WebPkiServerVerifier::builder(roots).build()?;
        Ok(Self { inner, allow_list })
    }
}

impl ServerCertVerifier for AllowListServerVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(cert, intermediates, server_name, ocsp, now)?;

        let fingerprint_hex = Cert::get_fingerprint_hex(cert)
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
            let err = io::Error::other(format!("Unauthorized fingerprint: {fingerprint_hex}"));
            Err(RustlsError::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(err)),
            )))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Debug)]
pub struct AllowListClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allow_list: Arc<Mutex<AllowList>>,
}

impl AllowListClientVerifier {
    pub fn new(
        allow_list: Arc<Mutex<AllowList>>,
        roots: Arc<rustls::RootCertStore>,
    ) -> Result<Self, VerifierBuilderError> {
        let inner = WebPkiClientVerifier::builder(roots).build()?;
        Ok(Self { inner, allow_list })
    }
}
impl ClientCertVerifier for AllowListClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.inner.verify_client_cert(cert, intermediates, now)?;

        let fingerprint_hex = Cert::get_fingerprint_hex(cert)
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
            let err = io::Error::other(format!("Unauthorized fingerprint: {fingerprint_hex}"));
            Err(RustlsError::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(err)),
            )))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::rand_core::OsRng;
    use rustls::RootCertStore;

    const TEST_RSA_BITS: usize = 2048;

    fn roots_for(cert: &Cert) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone().get_ca_cert_der().unwrap()).unwrap();
        Arc::new(roots)
    }

    /// Test that a certificate's public key hash is consistent across different ways of constructing it.
    #[test]
    fn test_cert_pubk_hash_consistency() {
        // The privk constructors sign with PKCS_RSA_SHA256, so they need an RSA key.
        // Cert::new picks its own algorithm instead and is therefore a separate identity below.
        let key = Cert::generate_private_key(&mut OsRng, TEST_RSA_BITS).unwrap();
        let from_privk = Cert::new_with_privk(&key).unwrap();
        let with_explicit_ca = Cert::new_with_privk_and_ca(&key, CA_KEY).unwrap();

        // The identity follows the key, not the certificate built around it.
        let hash = from_privk.get_pubk_hash().unwrap();
        assert_eq!(with_explicit_ca.get_pubk_hash().unwrap(), hash);
        assert_eq!(hash.len(), 64); // Hex of a SHA256 digest.

        // What the allow list compares at handshake time is derived from the certificate on the wire.
        let chain = from_privk.get_cert().unwrap();
        assert!(!chain.is_empty());
        assert_eq!(Cert::get_fingerprint_hex(&chain[0]).unwrap(), hash);

        // The bit string hash covers only the key inside the SPKI, so it is a different digest.
        let bitstring = from_privk._get_bitstring_pubk_hash().unwrap();
        assert_eq!(bitstring.len(), 64);
        assert_ne!(bitstring, hash);

        assert!(from_privk.get_private_key().is_ok());
        assert!(!from_privk.clone().get_ca_cert_der().unwrap().is_empty());

        // A different key is a different identity.
        let generated = Cert::new().unwrap();
        assert_ne!(generated.get_pubk_hash().unwrap(), hash);
        assert!(generated.get_private_key().is_ok());
    }

    /// Test that a certificate can be saved to files and loaded back, preserving its identity.
    #[test]
    fn test_cert_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().into_owned();

        // generate_key_file creates the directory, so it is given one that does not exist yet.
        let nested = format!("{path}/certs");
        Cert::generate_key_file(&nested, "node", &mut OsRng, TEST_RSA_BITS).unwrap();

        let from_key = Cert::from_key_file(&format!("{nested}/node.key")).unwrap();
        let hash = from_key.get_pubk_hash().unwrap();

        // from_file reads a certificate beside the key and takes the identity from the certificate.
        std::fs::write(format!("{nested}/node.pem"), &from_key.cert_pem).unwrap();
        let from_file = Cert::from_file(&nested, "node").unwrap();
        assert_eq!(from_file.get_pubk_hash().unwrap(), hash);

        // A missing file is reported.
        assert!(Cert::from_key_file(&format!("{nested}/absent.key")).is_err());
        assert!(Cert::from_file(&nested, "absent").is_err());
    }

    /// Test that both server and client verifiers can be built on the same CA and answer for the handshake.
    #[test]
    fn test_server_client_verifiers() {
        let cert = Cert::new().unwrap();
        let allow_list = AllowList::new();

        let server = AllowListServerVerifier::new(allow_list.clone(), roots_for(&cert)).unwrap();
        let client = AllowListClientVerifier::new(allow_list, roots_for(&cert)).unwrap();

        // Both wrap a webpki verifier.
        assert_eq!(
            server.supported_verify_schemes(),
            client.supported_verify_schemes()
        );

        // A client certificate is asked for and required.
        assert!(client.offer_client_auth());
        assert!(client.client_auth_mandatory());
        let _ = client.root_hint_subjects();
    }
}
