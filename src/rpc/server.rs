use super::errors::BrokerError;
use super::{BrokerConfig, Message, StorageApi};
use crate::rpc::tls_helper::AcceptAllClientCerts;
use crate::rpc::Broker;
use futures::prelude::*;
use hex;
use ring::digest::{digest, SHA256};
use rustls::ServerConfig;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};
use tarpc::serde_transport;
use tarpc::{
    context,
    server::{self, Channel},
    tokio_serde::formats::Json,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{error, info};
use x509_parser::parse_x509_certificate;

#[derive(Clone)]
struct BrokerServer<S: StorageApi> {
    _peer: SocketAddr,
    storage: Arc<Mutex<S>>,
}

impl<S> BrokerServer<S>
where
    S: StorageApi,
{
    fn new(peer: SocketAddr, storage: Arc<Mutex<S>>) -> Self {
        Self {
            _peer: peer,
            storage,
        }
    }
}

impl<S> Broker for BrokerServer<S>
where
    S: StorageApi + 'static + Send + Sync,
{
    async fn send(self, _: context::Context, from: u32, dest: u32, msg: String) -> bool {
        self.storage.lock().unwrap().insert(from, dest, msg);
        true
    }

    async fn get(self, _: context::Context, dest: u32) -> Option<Message> {
        self.storage.lock().unwrap().get(dest)
    }

    async fn ack(self, _: context::Context, dest: u32, uid: u64) -> bool {
        self.storage.lock().unwrap().remove(dest, uid)
    }
}

async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}

type ShutDownSignal = mpsc::Receiver<()>;
pub async fn run<S>(
    mut shutdown: ShutDownSignal,
    storage: Arc<Mutex<S>>,
    config: BrokerConfig,
) -> anyhow::Result<()>
where
    S: 'static + Send + Sync + StorageApi + Clone,
{
    let server_addr = (
        config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        config.port,
    );
    let listener = TcpListener::bind(server_addr).await?;
    info!(
        "Listening with TLS on port {}",
        listener.local_addr()?.port()
    );

    // Load certs, private key, and allowlist
    let allowlist = config.cert_files.load_allowlist_from_yaml()?;
    let certs = config.cert_files.load_certs()?;
    let key = config.cert_files.load_private_key()?;

    // Server config
    let client_auth = Arc::new(AcceptAllClientCerts);
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs, key)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(config));

    tokio::select! {
        _ = async {
            loop {
                info!("Server started, waiting for TLS connections...");
                let (stream, addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("TCP accept error: {:?}", e);
                        continue;
                    }
                };

                // Clone for async task
                let acceptor = tls_acceptor.clone();
                let allowlist = allowlist.clone();
                let storage = storage.clone();

                // Spawn a new task for each connection
                tokio::spawn(async move {

                    // Perform TLS handshake
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            tls_stream
                        },
                        Err(e) => {
                            error!("TLS handshake failed: {:?}", e);
                            return;
                        }
                    };

                    // Get client certificate
                    let client_cert_der = tls_stream
                        .get_ref()
                        .1
                        .peer_certificates();
                    let client_cert_der = match client_cert_der {
                        Some(certs) => certs[0].as_ref(),
                        None => {
                            error!("No client certificate found");
                            return;
                        }
                    };
                    let (_, parsed_cert) = parse_x509_certificate(client_cert_der)
                    .map_err(|e| BrokerError::TlsError(format!("Failed to parse certificate: {:?}", e))).unwrap();

                    // Extract subject public key info (SPKI)
                    let spki = parsed_cert
                        .tbs_certificate
                        .subject_pki
                        .subject_public_key
                        .data;

                    // Verify client certificate against allow list
                    let fingerprint = digest(&SHA256, &spki);
                    let fingerprint_hex = hex::encode(fingerprint.as_ref());
                    if allowlist.contains_key(&fingerprint_hex) {
                        info!("Client is authorized!");
                        let framed = Framed::new(tls_stream, LengthDelimitedCodec::new()); // Length prefix, message boundaries
                        let transport = serde_transport::new(framed, Json::default());
                        server::BaseChannel::with_defaults(transport)
                            .execute(BrokerServer::new(addr, storage).serve())
                            .for_each(spawn)
                            .await;
                    } else {
                        info!("Unauthorized client fingerprint: {}", fingerprint_hex);
                    }
                });
            }
        } => {},
        _ = shutdown.recv() => {
            info!("Shutting down...");
        },
    }

    Ok(())
}
