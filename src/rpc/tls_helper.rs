use crate::identification::allow_list::AllowList;
use crate::rpc::errors::BrokerError;
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
    sync::Once,
    sync::{Arc, Mutex},
};
use tracing::info;
use x509_parser::{der_parser::der::parse_der_sequence, parse_x509_certificate};

const CA_KEY: &str = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzkbFynswfys/\nVNbM4hzYNKCdAuxYI/jysOPkRHGhlJe+71EE9F2CpAZnjevBsUWxi3+LatfMZjwi\nUz/l3iC6ow8Dsar0BO6RmWQR8Uf/1sx+WNjBk2woISPb60oXbXYj8AVUqYUUSo/Q\nRF5kuGT7dsMvUAx8Irn93w4A5VXx+FLn3r38Tymv7qOMT5cO1xrNStsluBD1RdPj\nz+B6b+7woAKqkrNFR+ZH0HUUKldA+A+pGElQLODyLB7OwxHgKtEsFdyiiDuKW2mP\nsk2dsab9HCNdo9cViA9UbeykDXq7h0/7gYg9XBH8LqqXYpSk/LE6T8k1RVa9EBxV\nRpYqlvFPAgMBAAECggEAV64pfRQq0aIPwP/IiLYkTS/iThWcgH03ZcWaOED7fqqc\nYd+7rhjVVq0qb3uEWCnlzhNE63YJZa0tHIcHANNIEjDO27hZkXd4y8CsQutV8doO\nfeEyCbic/tgffH3Yv1AZ18qTx1QsAL0TKuPhY2rWi26KTAzhTDKP1iyO23ox7Uqs\nwWChuHWyw7SmECRmjKOjTLs1Axea3fos6ERgEv/KZiTi+a9he5JuHOXO6aKTvHI7\nlTAMdloy1CnK6G3Ql7LfBeX20hIwDSZNgp5naB6NjJiDTbxxlGj7apW6hquzJpRP\n1Tn2YLvVKl5bdAOHh44wHBhZR9COjxUT+uASYRb5wQKBgQD7FTe3VPrsi6ejo7db\n9SwTUjsTQKoxrfoNc0xPzGGwKyyArGM++NQI1CZuQQDXVoYl+JC1JOcTLjjW/TYu\nwVGAr63bjtYjU0e8NZzum3nIZ7rpyHJpnbCLBc678KNCvblD4u/Vl1bx/9vRiCTx\n9S0r/LJ54Jr3Ohx9feYERc4K/QKBgQDmOlWNHwFlC2pkYI/0biXWybQZWvz+C5x3\nJO6tf0ykRk2sBEcp07JMhJsE+r4B+lHNSWalkX409Fn6x2ch/6tLP0X+viM5nr+2\nRpGHLpUBeq4+RKMmUS/NgY2DoRV1DRnfk4Vt0BZy5Voc4OVQz0zohwFzYhY60ThR\nV3UJ9HbdOwKBgQCcBS8+CNxzqMRe9xi1V8AvsWVsLT6U6Fr9iKve2k3JvspEmtqB\nAvYfFlVbJaF0Lhvl9HNXXLsKPCqtzWKh4xbWNFSAnl2KTfHBjj8aNhqS4YJQS3Jt\nFsPhX5Z7SqjojCRXfukxfH1Wm3ro1QTAJW4Qa1IsUdl5zu5tPJJ2DTpfsQKBgCii\nXR0mPsnFxQZoYKAEnNsXCJl9DLAN/pSsyQ+IK0/HNMhKjQDd41dMBExRsR2KP8va\ny6onTr4r7oGrlhFTHbmPNlxq1K7DzRRvyhmw6A21yHEnDiCiLay40/BKiw34vPtP\n/znNg1jOECSOsQqdO/bCdUgXJNNGwAjjRb33Ds+nAoGAW76wLk1lwD2tZ8KgMRUU\ni0BkY7eDXPskxCP6BjFq10J/1dC/dsLO9mZfwl2BJ2D+gGmcIzdSb5p1LkuniGuv\nV+/lSa8bdUKwtd5l+CZ0OMqmHryQZICqGeG5uREYv5eqs4mDiuM8QkZdOZUKWzPc\nwWJXrp5cQtvgjS/HyjHB69o=\n-----END PRIVATE KEY-----\n'";

#[derive(Debug, Clone)]
pub struct Cert {
    key_pem: String,
    cert_pem: String,
    spki_der: Vec<u8>,
    ca_der: Vec<u8>,
}

impl Cert {
    pub fn new() -> Result<Self, BrokerError> {
        let cert = Self::create_cert(None)?;
        let (key_pem, cert_pem, spki_der, ca_der) = Self::get_vars(&cert, CA_KEY)?;
        info!("Created new certificate");
        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
            ca_der,
        })
    }
    /// privk is a hex string in PEM format.
    pub fn new_with_privk(privk: &str) -> Result<Self, BrokerError> {
        let cert = Self::create_cert(Some(privk))?;
        let (key_pem, cert_pem, spki_der, ca_der) = Self::get_vars(&cert, CA_KEY)?;
        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
            ca_der,
        })
    }
    pub fn from_key_file(key_path: &str) -> Result<Self, BrokerError> {
        let key_pem = std::fs::read_to_string(key_path)?;
        let cert = Self::create_cert(Some(&key_pem))?;
        let (generated_key_pem, cert_pem, spki_der, ca_der) = Self::get_vars(&cert, CA_KEY)?;
        Ok(Self {
            key_pem: generated_key_pem,
            cert_pem,
            spki_der,
            ca_der,
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

        let ca = Self::load_ca(CA_KEY)?;
        let ca_der = ca.serialize_der()?;
        Ok(Self {
            key_pem,
            cert_pem,
            spki_der,
            ca_der,
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
        std::fs::create_dir_all(path)?;
        let key_path = format!("{path}/{name}.key");
        std::fs::write(key_path, key)?;
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
    pub fn get_pubk_hash(&self) -> Result<String, BrokerError> {
        let _pubk_hexstring = hex::encode(&self.spki_der);
        let fingerprint = Sha256::digest(&self.spki_der);
        let hexsum = hex::encode(fingerprint);
        Ok(hexsum)
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

    pub fn get_pubk_hash_from_privk(privk: &str) -> Result<String, BrokerError> {
        let cert = Cert::new_with_privk(privk)?;
        let fingerprint = cert.get_pubk_hash()?;
        Ok(fingerprint)
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

static INIT_TLS: Once = Once::new();

pub fn init_tls() {
    INIT_TLS.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
