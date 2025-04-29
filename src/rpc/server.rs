use super::{BrokerConfig, Message, StorageApi};
use crate::rpc::tls_helper::{load_certs, load_private_key};
use crate::rpc::Broker;
use futures::{future, prelude::*};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile;
use std::any;
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
use tracing::info;

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

    let certs = load_certs("cert.pem")?;
    let key = load_private_key("key.pem")?;
    let tls_config = ServerConfig::builder()
        .with_no_client_auth() // Server does not require the client to present a certificate
        .with_single_cert(certs, key)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    tokio::select! {
        _ = async {
            loop {  // Waiting for incoming connections
                let (stream, addr) = listener.accept().await.unwrap();
                let tls_acceptor = tls_acceptor.clone();
                let storage = storage.clone();

                tokio::spawn(async move {   // One stream per client
                    let tls_stream = match tls_acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("TLS accept error: {:?}", e);
                            return;
                        }
                    };

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
