use super::errors::BrokerError;
use crate::{
    identification::{allow_list::AllowList, identifier::Identifier},
    rpc::{
        errors::MutexExt,
        tls_helper::{AllowListServerVerifier, Cert},
        BrokerClient, BrokerConfig, Message, MAX_FRAME_SIZE_KB, MAX_MSG_SIZE_KB,
    },
};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex as ArcMutex},
};
use tarpc::{client, context, serde_transport, tokio_serde::formats::Json};
use tokio::{net::TcpStream, sync::Mutex};
use tokio_rustls::{rustls::ClientConfig, TlsConnector};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::info;

#[derive(Debug)]
pub struct Client {
    address: SocketAddr,
    client: Arc<Mutex<Option<BrokerClient>>>,
    cert: Cert,
    allow_list: Arc<ArcMutex<AllowList>>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        self.try_clone().expect("failed to clone Client")
    }
}

impl Client {
    pub fn new(config: &BrokerConfig, cert: Cert, allow_list: Arc<ArcMutex<AllowList>>) -> Self {
        let address = SocketAddr::new(
            config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            config.port,
        );
        info!("Client address: {}", address);
        Self {
            address,
            client: Arc::new(Mutex::new(None)),
            cert,
            allow_list,
        }
    }

    async fn connect(&self) -> Result<(), BrokerError> {
        let stream = TcpStream::connect(self.address).await?;
        stream.set_nodelay(true)?;

        // Load certs and private key
        let cert = self.cert.get_cert()?;
        let key = self.cert.get_private_key()?;
        let ca_cert_der = self.cert.clone().get_ca_cert_der()?;

        // Load CA
        let mut roots = RootCertStore::empty();
        roots.add(ca_cert_der)?;

        // Client config
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                AllowListServerVerifier::new(self.allow_list.clone(), roots.into())
                    .map_err(|e| BrokerError::TlsError(e.to_string()))?,
            ))
            .with_client_auth_cert(cert, key)
            .map_err(|e| BrokerError::TlsError(e.to_string()))?;

        // Load certificate
        let connector = TlsConnector::from(Arc::new(config));
        let domain =
            ServerName::try_from("localhost").map_err(|e| BrokerError::TlsError(e.to_string()))?;
        let tls_stream = connector.connect(domain, stream).await?;
        let peer_certs = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .ok_or_else(|| BrokerError::TlsError("No peer certificate".into()))?;
        let server_cert = peer_certs
            .first()
            .ok_or_else(|| BrokerError::TlsError("Empty peer certificate list".into()))?;

        // Check against allow list
        let server_fingerprint = Cert::get_fingerprint_hex(server_cert)
            .map_err(|e| BrokerError::TlsError(format!("Fingerprint error: {e}")))?;
        let peer_addr = tls_stream.get_ref().0.peer_addr()?;
        let ipaddr = IpAddr::from_str(&peer_addr.ip().to_string())?;
        let allow = self
            .allow_list
            .lock_or_err::<BrokerError>("allow_list")?
            .is_allowed(&server_fingerprint, ipaddr);

        if !allow {
            drop(tls_stream);
            return Err(BrokerError::UnauthorizedFingerprint(server_fingerprint));
        }

        // Server is authorized
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_FRAME_SIZE_KB * 1024)
            .new_codec();
        let framed = Framed::new(tls_stream, codec);
        let transport = serde_transport::new(framed, Json::default());
        let client = BrokerClient::new(client::Config::default(), transport).spawn();
        let mut locked = self.client.lock().await;
        *locked = Some(client);
        Ok(())
    }

    async fn get_or_connect(&self) -> Result<BrokerClient, BrokerError> {
        {
            let mut locked = self.client.lock().await;

            if let Some(client) = locked.as_ref().cloned() {
                if client.ping(context::current()).await.is_ok() {
                    return Ok(client);
                }
                *locked = None;
            }
        }

        // Try reconnecting
        if self.connect().await.is_ok() {
            let locked = self.client.lock().await;
            if let Some(client) = locked.as_ref().cloned() {
                return Ok(client);
            }
        }
        Err(BrokerError::Disconnected)
    }

    pub async fn async_send_msg(
        &self,
        from_id: u8,
        dest: Identifier,
        msg: String,
    ) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;

        if msg.len() > MAX_MSG_SIZE_KB * 1024 {
            return Err(BrokerError::MessageTooLarge);
        }

        Ok(client
            .send(context::current(), from_id, dest, msg)
            .await??)
    }

    pub async fn async_get_msg(&self, dest: u8) -> Result<Option<Message>, BrokerError> {
        let client = self.get_or_connect().await?;
        let msg = client.get(context::current(), dest).await??;
        if let Some(ref m) = msg {
            if m.msg.len() > MAX_MSG_SIZE_KB * 1024 {
                return Err(BrokerError::MessageTooLarge);
            }
        }
        Ok(msg)
    }

    pub async fn async_ack(&self, dest: u8, uid: u64) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.ack(context::current(), dest, uid).await??)
    }

    fn try_clone(&self) -> Result<Self, BrokerError> {
        Ok(Self {
            address: self.address,
            client: Arc::clone(&self.client),
            cert: self.cert.clone(),
            allow_list: self.allow_list.clone(),
        })
    }
}
