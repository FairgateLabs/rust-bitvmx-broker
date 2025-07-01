use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use crate::rpc::tls_helper::{CertFiles, NoVerifier};
use ring::digest::{digest, SHA256};
use rustls::pki_types::ServerName;
use x509_parser::parse_x509_certificate;

use crate::rpc::BrokerClient;
use tarpc::{client, context, serde_transport, tokio_serde::formats::Json};
use tokio::{net::TcpStream, runtime::Runtime, sync::Mutex};
use tokio_rustls::{rustls::ClientConfig, TlsConnector};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::info;

use super::{errors::BrokerError, BrokerConfig, Message};

pub struct Client {
    rt: Runtime,
    address: SocketAddr,
    client: Arc<Mutex<Option<BrokerClient>>>,
    cert_files: CertFiles,
    allow_list: HashMap<String, String>,
}

impl Client {
    pub fn new(config: &BrokerConfig) -> Result<Self, BrokerError> {
        let rt = Runtime::new()?;
        let address = SocketAddr::new(
            config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            config.port,
        );
        let cert_files = config.cert_files.clone();
        let allow_list = cert_files.load_allowlist_from_yaml()?;
        Ok(Self {
            rt,
            address,
            client: Arc::new(Mutex::new(None)),
            cert_files,
            allow_list,
        })
    }

    async fn connect(&self) -> Result<(), BrokerError> {
        let stream = TcpStream::connect(self.address).await?;
        stream.set_nodelay(true)?;

        // Load certs and private key
        let cert = self.cert_files.load_certs()?;
        let key = self.cert_files.load_private_key()?;

        // Client config
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_client_auth_cert(cert, key)
            .map_err(|e| BrokerError::TlsError(e.to_string()))?;

        // Load certificate
        let connector = TlsConnector::from(Arc::new(config));
        let domain =
            ServerName::try_from("localhost").map_err(|e| BrokerError::TlsError(e.to_string()))?;
        let tls_stream = connector.connect(domain, stream).await?;

        // Verify server certificate against allow list
        let server_cert_der =
            tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .ok_or(BrokerError::TlsError(
                    "No server certificate found".to_string(),
                ))?[0]
                .as_ref();
        let (_, parsed_cert) = parse_x509_certificate(server_cert_der)
            .map_err(|e| BrokerError::TlsError(format!("Failed to parse certificate: {:?}", e)))?;

        // Extract subject public key info (SPKI)
        let spki = parsed_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data;

        // Hash the public key
        let fingerprint = digest(&SHA256, &spki);
        let fingerprint_hex = hex::encode(fingerprint.as_ref());

        if !self.allow_list.contains_key(&fingerprint_hex) {
            info!("Unauthorized server fingerprint: {}", fingerprint_hex);
            return Err(BrokerError::UnauthorizedFingerprint(fingerprint_hex));
        }

        // Else the server is authorized
        info!("Server is authorized!");
        let framed = Framed::new(tls_stream, LengthDelimitedCodec::new());
        let transport = serde_transport::new(framed, Json::default());
        let client = BrokerClient::new(client::Config::default(), transport).spawn();
        let mut locked = self.client.lock().await;
        *locked = Some(client);
        Ok(())
    }

    async fn get_or_connect(&self) -> Result<BrokerClient, BrokerError> {
        let mut locked = self.client.lock().await;

        if locked.is_none() {
            drop(locked); // release lock before await
            self.connect().await?;
            locked = self.client.lock().await;
        }

        locked
            .as_ref()
            .cloned()
            .ok_or_else(|| BrokerError::Disconnected)
    }

    async fn async_send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.send(context::current(), from, dest, msg).await?)
    }

    async fn async_get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.get(context::current(), dest).await?)
    }

    async fn async_ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.ack(context::current(), dest, uid).await?)
    }

    pub fn send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_send_msg(from, dest, msg))
    }

    pub fn get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        self.rt.block_on(self.async_get_msg(dest))
    }

    pub fn ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_ack(dest, uid))
    }
}
