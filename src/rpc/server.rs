use super::{BrokerConfig, Message, StorageApi};
use crate::rpc::{tls_helper::ArcAllowList, Broker};
use futures::prelude::*;
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
    let allowlist: Arc<Mutex<crate::allow_list::AllowList>> = config.allow_list;
    let certs = config.cert.get_cert()?;
    let key = config.cert.get_private_key()?;

    // Server config
    let client_auth = Arc::new(ArcAllowList::new(allowlist));
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


                // Client is authorized
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
