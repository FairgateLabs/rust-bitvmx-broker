use super::{BrokerConfig, Message, StorageApi};
use crate::rpc::tls_helper::{
    get_whitelist_path, load_certs, load_private_key, load_whitelist_from_yaml,
};
use crate::rpc::Broker;
use futures::{future, prelude::*};
use hex;
use ring::digest::{digest, SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile;
use std::any;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
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
    let whitelist = load_whitelist_from_yaml(&get_whitelist_path()?)?;

    let server_addr = (
        config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        config.port,
    );

    let listener = TcpListener::bind(server_addr).await?;
    info!(
        "Listening with TLS on port {}",
        listener.local_addr()?.port()
    );

    let ca_certs = load_certs("certs/ca.pem")?;
    let certs = load_certs("certs/server.pem")?;
    let key = load_private_key("certs/server.key")?;

    let mut client_root = RootCertStore::empty();
    for cert in ca_certs {
        client_root.add(cert)?;
    }

    let client_auth = WebPkiClientVerifier::builder(client_root.into()).build()?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        // .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(config));

    tokio::select! {
        _ = async {
            loop {
                info!("Server started, waiting for TLS connections...");
                let (stream, addr) = listener.accept().await.unwrap();
                let acceptor = tls_acceptor.clone();
                let whitelist = whitelist.clone();
                let storage = storage.clone();

                tokio::spawn(async move {
                    // let tls_stream = acceptor.accept(stream).await.unwrap();
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            tls_stream
                        },
                        Err(e) => {
                            error!("TLS handshake failed: {:?}", e);
                            return;
                        }
                    };

                    // let client_cert = tls_stream.get_ref().1.peer_certificates().unwrap()[0].as_ref();

                    // let parsed = x509_parser::parse_x509_certificate(client_cert).unwrap().1;
                    // let cn = parsed.subject().iter_common_name().next().unwrap().as_str().unwrap();
                    // info!("Client CN = {}", cn);

                    // if whitelist.contains_key(cn) {
                    //     info!("Client '{}' is authorized!", cn);
                    //     // proceed with protocol handling
                    // } else {
                    //     info!("Client '{}' is NOT authorized!", cn);
                    // }

                    let client_cert_der = tls_stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .unwrap()[0]
                        .as_ref();

                    // Compute SHA-256 hash of the certificate
                    let fingerprint = digest(&SHA256, client_cert_der);
                    let fingerprint_hex = hex::encode(fingerprint.as_ref());

                    info!("Client fingerprint = {}", fingerprint_hex);

                    if whitelist.contains_key(&fingerprint_hex) {
                        info!("Client is authorized!");
                    } else {
                        info!("Unauthorized client fingerprint: {}", fingerprint_hex);
                    }

                    let framed = Framed::new(tls_stream, LengthDelimitedCodec::new()); // Length prefix, message boundaries
                            let transport = serde_transport::new(framed, Json::default());

                    server::BaseChannel::with_defaults(transport)
                        .execute(BrokerServer::new(addr, storage).serve())
                        .for_each(spawn)
                        .await;
                });
            }
        } => {},
        _ = shutdown.recv() => {
            info!("Shutting down...");
        },
    }

    Ok(())
}
