use bitvmx_broker::{
    channel::channel::{DualChannel, LocalChannel},
    identification::{allow_list::AllowList, identifier::Identifier, routing::RoutingTable},
    rpc::{
        client::Client, errors::BrokerError, sync_server::BrokerSync, tls_helper::Cert,
        BrokerConfig,
    },
};
use std::{
    fs::{self},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tarpc::client::RpcError;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

#[cfg(not(feature = "storagebackend"))]
use bitvmx_broker::broker_memstorage::MemStorage;
#[cfg(feature = "storagebackend")]
use bitvmx_broker::broker_storage::BrokerStorage;
#[cfg(feature = "storagebackend")]
use storage_backend::{storage::Storage, storage_config::StorageConfig};

#[cfg(not(feature = "storagebackend"))]
fn prepare_server(
    port: u16,
    privk_pem: &str,
    allow_list: Arc<Mutex<AllowList>>,
    routing: Arc<Mutex<RoutingTable>>,
) -> (BrokerSync, LocalChannel<MemStorage>) {
    let storage = Arc::new(Mutex::new(MemStorage::new()));
    let server_cert = Cert::new_with_privk(privk_pem).unwrap();
    let server_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_cert.get_pubk_hash().unwrap(),
        None,
    )
    .unwrap();
    let server = BrokerSync::new(
        &server_config,
        storage.clone(),
        server_cert,
        allow_list.clone(),
        routing,
    );
    let my_address = get_local_addr(port);
    let local = LocalChannel::new(
        Identifier {
            pubkey_hash: "local".to_string(),
            id: Some(0),
            address: my_address,
        },
        storage,
    );
    (server, local)
}

#[cfg(feature = "storagebackend")]
fn prepare_server(
    port: u16,
    privk_pem: &str,
    allow_list: Arc<Mutex<AllowList>>,
    routing: Arc<Mutex<RoutingTable>>,
) -> (BrokerSync, LocalChannel<BrokerStorage>) {
    let storage_path = format!("storage_{}.db", port);
    let config = StorageConfig::new(storage_path.clone(), None);
    let broker_backend = Storage::new(&config)
        .map_err(|e| BrokerError::StorageError(e.to_string()))
        .unwrap();
    let broker_backend = Arc::new(Mutex::new(broker_backend));
    let storage = Arc::new(Mutex::new(BrokerStorage::new(broker_backend)));

    let server_cert = Cert::new_with_privk(privk_pem).unwrap();
    let server_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_cert.get_pubk_hash().unwrap(),
        None,
    )
    .unwrap();
    let server = BrokerSync::new(
        &server_config,
        storage.clone(),
        server_cert,
        allow_list.clone(),
        routing,
    );
    let my_address = get_local_addr;
    let local = LocalChannel::new(
        Identifier {
            pubkey_hash: "local".to_string(),
            id: Some(0),
            address: my_address,
        },
        storage,
    );
    (server, local)
}

fn prepare_client(
    server_port: u16,
    server_pubk_hash: &str,
    client_privk_pem: &str,
    allow_list: Arc<Mutex<AllowList>>,
) -> DualChannel {
    prepare_client_with_id(
        server_port,
        server_pubk_hash,
        client_privk_pem,
        None,
        allow_list,
    )
}

fn prepare_client_with_id(
    server_port: u16,
    server_pubk_hash: &str,
    client_privk_pem: &str,
    id: Option<u8>,
    allow_list: Arc<Mutex<AllowList>>,
) -> DualChannel {
    let client_cert = Cert::new_with_privk(client_privk_pem).unwrap();
    let server_config = BrokerConfig::new(
        server_port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_pubk_hash.to_string(),
        None,
    )
    .unwrap();
    let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    let user = DualChannel::new(&server_config, client_cert, id, my_address, allow_list).unwrap();
    user
}

struct KeyPair {
    privk: String,
    pubk_hash: String,
    id: u8,
    port: u16,
}
impl KeyPair {
    fn new(privk: &str, port: u16) -> Self {
        let cert = Cert::new_with_privk(privk).unwrap();
        let pubk_hash = cert.get_pubk_hash().unwrap();
        Self {
            privk: privk.to_string(),
            pubk_hash,
            id: 0, // Default id to 0
            port,
        }
    }
    fn new_with_id(privk: &str, id: u8, port: u16) -> Self {
        let cert = Cert::new_with_privk(privk).unwrap();
        let pubk_hash = cert.get_pubk_hash().unwrap();
        Self {
            privk: privk.to_string(),
            pubk_hash,
            id,
            port,
        }
    }
    fn get_pkh(&self) -> String {
        self.pubk_hash.clone()
    }
    fn get_identifier(&self) -> Identifier {
        Identifier {
            pubkey_hash: self.pubk_hash.clone(),
            id: Some(self.id),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port),
        }
    }
}
fn cleanup_storage(port: u16) {
    let _ = fs::remove_dir_all(&PathBuf::from(format!("storage_{}.db", port)));
}
fn create_allow_list(identifiers: Vec<Identifier>) -> Arc<Mutex<AllowList>> {
    let allow_list = AllowList::new();
    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    {
        let mut allow_list = allow_list.lock().unwrap();
        for id in identifiers {
            allow_list.add(id.pubkey_hash, addr);
        }
    }
    allow_list
}
fn route_all() -> Arc<Mutex<RoutingTable>> {
    let routing = RoutingTable::new();
    {
        let mut routing = routing.lock().unwrap();
        routing.allow_all();
    }
    routing
}

fn get_keys(port: u16) -> (KeyPair, KeyPair, KeyPair) {
    let privk1 = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzkbFynswfys/\nVNbM4hzYNKCdAuxYI/jysOPkRHGhlJe+71EE9F2CpAZnjevBsUWxi3+LatfMZjwi\nUz/l3iC6ow8Dsar0BO6RmWQR8Uf/1sx+WNjBk2woISPb60oXbXYj8AVUqYUUSo/Q\nRF5kuGT7dsMvUAx8Irn93w4A5VXx+FLn3r38Tymv7qOMT5cO1xrNStsluBD1RdPj\nz+B6b+7woAKqkrNFR+ZH0HUUKldA+A+pGElQLODyLB7OwxHgKtEsFdyiiDuKW2mP\nsk2dsab9HCNdo9cViA9UbeykDXq7h0/7gYg9XBH8LqqXYpSk/LE6T8k1RVa9EBxV\nRpYqlvFPAgMBAAECggEAV64pfRQq0aIPwP/IiLYkTS/iThWcgH03ZcWaOED7fqqc\nYd+7rhjVVq0qb3uEWCnlzhNE63YJZa0tHIcHANNIEjDO27hZkXd4y8CsQutV8doO\nfeEyCbic/tgffH3Yv1AZ18qTx1QsAL0TKuPhY2rWi26KTAzhTDKP1iyO23ox7Uqs\nwWChuHWyw7SmECRmjKOjTLs1Axea3fos6ERgEv/KZiTi+a9he5JuHOXO6aKTvHI7\nlTAMdloy1CnK6G3Ql7LfBeX20hIwDSZNgp5naB6NjJiDTbxxlGj7apW6hquzJpRP\n1Tn2YLvVKl5bdAOHh44wHBhZR9COjxUT+uASYRb5wQKBgQD7FTe3VPrsi6ejo7db\n9SwTUjsTQKoxrfoNc0xPzGGwKyyArGM++NQI1CZuQQDXVoYl+JC1JOcTLjjW/TYu\nwVGAr63bjtYjU0e8NZzum3nIZ7rpyHJpnbCLBc678KNCvblD4u/Vl1bx/9vRiCTx\n9S0r/LJ54Jr3Ohx9feYERc4K/QKBgQDmOlWNHwFlC2pkYI/0biXWybQZWvz+C5x3\nJO6tf0ykRk2sBEcp07JMhJsE+r4B+lHNSWalkX409Fn6x2ch/6tLP0X+viM5nr+2\nRpGHLpUBeq4+RKMmUS/NgY2DoRV1DRnfk4Vt0BZy5Voc4OVQz0zohwFzYhY60ThR\nV3UJ9HbdOwKBgQCcBS8+CNxzqMRe9xi1V8AvsWVsLT6U6Fr9iKve2k3JvspEmtqB\nAvYfFlVbJaF0Lhvl9HNXXLsKPCqtzWKh4xbWNFSAnl2KTfHBjj8aNhqS4YJQS3Jt\nFsPhX5Z7SqjojCRXfukxfH1Wm3ro1QTAJW4Qa1IsUdl5zu5tPJJ2DTpfsQKBgCii\nXR0mPsnFxQZoYKAEnNsXCJl9DLAN/pSsyQ+IK0/HNMhKjQDd41dMBExRsR2KP8va\ny6onTr4r7oGrlhFTHbmPNlxq1K7DzRRvyhmw6A21yHEnDiCiLay40/BKiw34vPtP\n/znNg1jOECSOsQqdO/bCdUgXJNNGwAjjRb33Ds+nAoGAW76wLk1lwD2tZ8KgMRUU\ni0BkY7eDXPskxCP6BjFq10J/1dC/dsLO9mZfwl2BJ2D+gGmcIzdSb5p1LkuniGuv\nV+/lSa8bdUKwtd5l+CZ0OMqmHryQZICqGeG5uREYv5eqs4mDiuM8QkZdOZUKWzPc\nwWJXrp5cQtvgjS/HyjHB69o=\n-----END PRIVATE KEY-----\n'";
    let privk2 = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCeJYILLK2EpGP9\nCrlEeHL1hYODftAUxJTacRezNNuyAqqP04H0IFffXhdz/f54HnYnaN1VrMGNQlR5\nBashFjZa7fVEFp3osVgNEPNu63MA1Gr7o4BakopRbMx7jUyhmlJXNP3VX5tZEha+\nV7GOZEeh2Ej3pehnE/E6SD16Ez9aaGydFgrMALHjT2NfucK0XCcDvMbq53PsBaLm\nnH5TLnvtZvYmdyDoUe+RvlwaRAHv4AWDOElhQrj970giHWY6i9QgqrlTIYN5cQrD\nM6kNj1SaBtCNpG/wIK3NMLW7PAYeEKTopwdsFuVL+1e0IAsTIVpDC1mb3r2GlPji\n0GaMLBAHAgMBAAECggEAFPHDvMYgfuIkqeULL1HCa9jQV5Bqb22vhxSWPnIgLH2k\n6CJrYhEMgjUcZwy68F6caFC/i3KzOYmQ1WxWQy4Fadp88pUKOcCO+EAH9WcyVmhL\neOMpAxXIQstlc3F9tiNRh2IpweIFGXFHWNMVXVXTlNAnrcCnvEsMVhsuJSY6bDcV\n5ejQKE8kM8F30FzD2mii36XamsreMpQBAIlm0i1HH/8PpynUQ12bb2M0T/FR9C5V\nAbfeLUOgrzWgBs9hxmlBzILusJFjv7OvwIkF97GgoAyLKqFmxzncwQUTqh9iH2Js\nemN6Qg+vPIg2Et8Ku9XEX+CSXvDwFckB2Z14jqQw8QKBgQDPHDzAFDSTl+aPH+vd\n01wxtaFyP7KP2OaRabW1qzTPww87agbN3wPJqBBf9lEjVeGNjLrp2NyHX6Wfnt5V\nlpeWts13/M43rju2JJwOrfZnwJsJgQ9ZEQw30e1LWeiGpr0kcWlv2059tEiKgBwY\nNlw6evsCyFjrIuSqgg3riO9xMQKBgQDDel5TfTJ3BJZlgFYnU1YxUZDQ1mcMDnSK\ntdRLdpVWTEkjzf0a6rGJYla0NoqQdH9qDfimVMY6+RQLZVdhhXDVnQuwV0CK9ERY\nQWy/PEoPvIagTXgKJ8fKLYcG420fJJtPmTSEoPZg1PXtuABNj/68bI7ONL5CY6gO\n8iFJU0sGtwKBgA6mlLWRuFZofGrLe0fp16+8hXsrflomocjPjYcYYVgBGGa/jVOq\n3v244c+oAP1a6eW1etNn/9GjtnegKWIskPScYdSHEZ9mt9qepFt1euTD/zOg6ZEH\nX7HjK8IUzhoYWXDmhOrgvKCvzCHgBhzAW63XXUJJIeEgSsS1Bn8O5MFBAoGAMuiv\noDa+6dg8AvtFdMBzdiyz9m+gLrelCmsIew7LHcqIUdbX0CbHTexagFykAbMVa91v\noIH7jmhIHB+sfi1ukXNxE9/lY0rycbm4RKXC9A45UY5bcOmjUrhArj6UsMOr3zMb\nRl9VSyqrUdnV2l1iDliHaJS76DZkEmBk4t/abkkCgYEAxkk3skKgRJPt2bFLzdHV\n3Au24P/Cyqf1LIfXpuJcMBfAhw55g6DOLR4O0BH+s7cZk8hrGVeI9WyhC5EgzZrF\nBjTlZFqFtsz5psj1oNqgr/JnO2fL3csxbDR81q9uSSzdlN7BlzBpdQahi53K9MHi\nZDNGUy5a/PopNnWSzfHYUas=\n-----END PRIVATE KEY-----\n'";
    let privk3 = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDK3zkTXQMEWbzL\nSRRBO7Wd657dQ/EifekFOIsDtiWHpjOdMRN9H25dVCkm5aBY2zNn62DzZcOlB57z\nUosALiPiyLrcDEu6w6efl3ZikkYD4gbfSKEAGDn1rLS/eUlM61hrgv7ibeqc8grA\nOo9ksWk9JKalCs0gRkufJn9fmiKmKDYDYkzMfSWZ0hDSL6kcy1ZfQLjDpwT6TJXm\nwVN7X6y25Men1v///qlXlBuIf/o1KtXG2v31NWHP0rxHiu5nCG1vGGenGF8y1puK\nVf+OhyqzPhter9gi5wqLo6QQjzyJt/71WDydVmjMDz30QDJrokV8JFu2zPJiG99u\nrIs9BqyfAgMBAAECggEAVn2ho0A5y46In3B6Gq+eqAOuuK3BLc/ZWxj2p2/uAy2X\n/rHQGb2fO1noq4UlfgyCF5FxxYNCzGZ53Un5KewB76tdgvgZBzhoC/GyjqbHA9vG\ny0X3IgeyGiv16VYHqqwBh+CS0y1CY4QLklXFEYxTjjZEd8OpnVNq5SCwGC2qDQT/\nSXOmY9YhZmE1gi5wsNhe3a03jLsn6ccekZ82jDI8z8zY0H8hfgf5yCDW23HgiHIB\ncGoFv1h+LWl2Qs+cTV9C98XEM/Xf/xBZC6fiydeNOY65OGnDDs1EtpB7KUxI/WKe\niHVAa9iZ1Rt+pJS9ebvfdU0Zim2iJmjA1RpdSwQvPQKBgQD9iMTXvdt6L/arNMhX\nnY+kjHZ/LWF0zWppXc0NHhL8YynyqDqe9ba6M1f+HAtZ/bFNGzmRNBJ/2D8s8js7\nMlfvzZ2Q0+Uhpr3YY4cOfT+WlCRWCoRMcn/EwrhpvV3OJA5jUSxIiroyWNPD3Bdl\nQeRL7LJAjkryfxNX/uCPGegTzQKBgQDM2FGakoqWZ3lMAwFOYRMnarbc5ZQ2Fly4\ns99elNDqMivcrY211Ni6ZcygvEs/vTB701l/w00K/NpF7UBaImj1FGjw1t+gG2IZ\n5VlHkk8+BahIn6nLK2/Ndkzla3I+LvLduU+n0FIQnx3r6tIX3R5yo453BigaSHq/\nvZLyH7TuGwKBgGIBmsYjOFJ1dA8eqktkNwDO44eqDUBPn9D3V6q4c3JpCvAoo/CK\n34X/DwbF5IV3EjDSU2CUFoqhF1rSkJ8DiQbEHyK7JpnpkP2zC6RIOmqE/b7c9eNv\nZ4CyHQOTFk33ljBCUrIAHpYTzFisHccgv5Wx+/4Eg2hWQy4C8t+ejh4JAoGBAJiL\n+3FV8fkBw7XUgxOAfUgcU2N7YH1K9+/gm9aOkmnlxP5JDMA9asyc5N9KeetUk5eT\nFBJuOaCWHmJ2xTaaa3kfouq/ybcszUiloHAJSBPTGLhElqijh1YF5EvxURl30wtF\nZkl9fK++HwVCUQTOeU879+sxXYn9MdQ6dAT1kcLDAoGAH0Pt2LzCX+loETpz2P3i\n4pWnQmc07kfF/KS80IFYRSs4hPO46kEHwstaQDH/6zM/LEow+nln+ribDW+tTQXq\nE/Z5XaLXjZzecdJid8gGGZXUAlbt6HAoftr3xRJTbL94uwNQlHILYwnrfFAPirp1\nrlxUtNVH/gHzfECrVUmwuCM=\n-----END PRIVATE KEY-----\n'";

    (
        KeyPair::new(privk1, port),
        KeyPair::new(privk2, port),
        KeyPair::new(privk3, port),
    )
}

fn get_keys_dif_id(port: u16) -> (KeyPair, KeyPair, KeyPair, KeyPair) {
    let privk1 = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzkbFynswfys/\nVNbM4hzYNKCdAuxYI/jysOPkRHGhlJe+71EE9F2CpAZnjevBsUWxi3+LatfMZjwi\nUz/l3iC6ow8Dsar0BO6RmWQR8Uf/1sx+WNjBk2woISPb60oXbXYj8AVUqYUUSo/Q\nRF5kuGT7dsMvUAx8Irn93w4A5VXx+FLn3r38Tymv7qOMT5cO1xrNStsluBD1RdPj\nz+B6b+7woAKqkrNFR+ZH0HUUKldA+A+pGElQLODyLB7OwxHgKtEsFdyiiDuKW2mP\nsk2dsab9HCNdo9cViA9UbeykDXq7h0/7gYg9XBH8LqqXYpSk/LE6T8k1RVa9EBxV\nRpYqlvFPAgMBAAECggEAV64pfRQq0aIPwP/IiLYkTS/iThWcgH03ZcWaOED7fqqc\nYd+7rhjVVq0qb3uEWCnlzhNE63YJZa0tHIcHANNIEjDO27hZkXd4y8CsQutV8doO\nfeEyCbic/tgffH3Yv1AZ18qTx1QsAL0TKuPhY2rWi26KTAzhTDKP1iyO23ox7Uqs\nwWChuHWyw7SmECRmjKOjTLs1Axea3fos6ERgEv/KZiTi+a9he5JuHOXO6aKTvHI7\nlTAMdloy1CnK6G3Ql7LfBeX20hIwDSZNgp5naB6NjJiDTbxxlGj7apW6hquzJpRP\n1Tn2YLvVKl5bdAOHh44wHBhZR9COjxUT+uASYRb5wQKBgQD7FTe3VPrsi6ejo7db\n9SwTUjsTQKoxrfoNc0xPzGGwKyyArGM++NQI1CZuQQDXVoYl+JC1JOcTLjjW/TYu\nwVGAr63bjtYjU0e8NZzum3nIZ7rpyHJpnbCLBc678KNCvblD4u/Vl1bx/9vRiCTx\n9S0r/LJ54Jr3Ohx9feYERc4K/QKBgQDmOlWNHwFlC2pkYI/0biXWybQZWvz+C5x3\nJO6tf0ykRk2sBEcp07JMhJsE+r4B+lHNSWalkX409Fn6x2ch/6tLP0X+viM5nr+2\nRpGHLpUBeq4+RKMmUS/NgY2DoRV1DRnfk4Vt0BZy5Voc4OVQz0zohwFzYhY60ThR\nV3UJ9HbdOwKBgQCcBS8+CNxzqMRe9xi1V8AvsWVsLT6U6Fr9iKve2k3JvspEmtqB\nAvYfFlVbJaF0Lhvl9HNXXLsKPCqtzWKh4xbWNFSAnl2KTfHBjj8aNhqS4YJQS3Jt\nFsPhX5Z7SqjojCRXfukxfH1Wm3ro1QTAJW4Qa1IsUdl5zu5tPJJ2DTpfsQKBgCii\nXR0mPsnFxQZoYKAEnNsXCJl9DLAN/pSsyQ+IK0/HNMhKjQDd41dMBExRsR2KP8va\ny6onTr4r7oGrlhFTHbmPNlxq1K7DzRRvyhmw6A21yHEnDiCiLay40/BKiw34vPtP\n/znNg1jOECSOsQqdO/bCdUgXJNNGwAjjRb33Ds+nAoGAW76wLk1lwD2tZ8KgMRUU\ni0BkY7eDXPskxCP6BjFq10J/1dC/dsLO9mZfwl2BJ2D+gGmcIzdSb5p1LkuniGuv\nV+/lSa8bdUKwtd5l+CZ0OMqmHryQZICqGeG5uREYv5eqs4mDiuM8QkZdOZUKWzPc\nwWJXrp5cQtvgjS/HyjHB69o=\n-----END PRIVATE KEY-----\n'";
    let privk2 = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCeJYILLK2EpGP9\nCrlEeHL1hYODftAUxJTacRezNNuyAqqP04H0IFffXhdz/f54HnYnaN1VrMGNQlR5\nBashFjZa7fVEFp3osVgNEPNu63MA1Gr7o4BakopRbMx7jUyhmlJXNP3VX5tZEha+\nV7GOZEeh2Ej3pehnE/E6SD16Ez9aaGydFgrMALHjT2NfucK0XCcDvMbq53PsBaLm\nnH5TLnvtZvYmdyDoUe+RvlwaRAHv4AWDOElhQrj970giHWY6i9QgqrlTIYN5cQrD\nM6kNj1SaBtCNpG/wIK3NMLW7PAYeEKTopwdsFuVL+1e0IAsTIVpDC1mb3r2GlPji\n0GaMLBAHAgMBAAECggEAFPHDvMYgfuIkqeULL1HCa9jQV5Bqb22vhxSWPnIgLH2k\n6CJrYhEMgjUcZwy68F6caFC/i3KzOYmQ1WxWQy4Fadp88pUKOcCO+EAH9WcyVmhL\neOMpAxXIQstlc3F9tiNRh2IpweIFGXFHWNMVXVXTlNAnrcCnvEsMVhsuJSY6bDcV\n5ejQKE8kM8F30FzD2mii36XamsreMpQBAIlm0i1HH/8PpynUQ12bb2M0T/FR9C5V\nAbfeLUOgrzWgBs9hxmlBzILusJFjv7OvwIkF97GgoAyLKqFmxzncwQUTqh9iH2Js\nemN6Qg+vPIg2Et8Ku9XEX+CSXvDwFckB2Z14jqQw8QKBgQDPHDzAFDSTl+aPH+vd\n01wxtaFyP7KP2OaRabW1qzTPww87agbN3wPJqBBf9lEjVeGNjLrp2NyHX6Wfnt5V\nlpeWts13/M43rju2JJwOrfZnwJsJgQ9ZEQw30e1LWeiGpr0kcWlv2059tEiKgBwY\nNlw6evsCyFjrIuSqgg3riO9xMQKBgQDDel5TfTJ3BJZlgFYnU1YxUZDQ1mcMDnSK\ntdRLdpVWTEkjzf0a6rGJYla0NoqQdH9qDfimVMY6+RQLZVdhhXDVnQuwV0CK9ERY\nQWy/PEoPvIagTXgKJ8fKLYcG420fJJtPmTSEoPZg1PXtuABNj/68bI7ONL5CY6gO\n8iFJU0sGtwKBgA6mlLWRuFZofGrLe0fp16+8hXsrflomocjPjYcYYVgBGGa/jVOq\n3v244c+oAP1a6eW1etNn/9GjtnegKWIskPScYdSHEZ9mt9qepFt1euTD/zOg6ZEH\nX7HjK8IUzhoYWXDmhOrgvKCvzCHgBhzAW63XXUJJIeEgSsS1Bn8O5MFBAoGAMuiv\noDa+6dg8AvtFdMBzdiyz9m+gLrelCmsIew7LHcqIUdbX0CbHTexagFykAbMVa91v\noIH7jmhIHB+sfi1ukXNxE9/lY0rycbm4RKXC9A45UY5bcOmjUrhArj6UsMOr3zMb\nRl9VSyqrUdnV2l1iDliHaJS76DZkEmBk4t/abkkCgYEAxkk3skKgRJPt2bFLzdHV\n3Au24P/Cyqf1LIfXpuJcMBfAhw55g6DOLR4O0BH+s7cZk8hrGVeI9WyhC5EgzZrF\nBjTlZFqFtsz5psj1oNqgr/JnO2fL3csxbDR81q9uSSzdlN7BlzBpdQahi53K9MHi\nZDNGUy5a/PopNnWSzfHYUas=\n-----END PRIVATE KEY-----\n'";

    (
        KeyPair::new(privk1, port),
        KeyPair::new_with_id(privk2, 0, port),
        KeyPair::new_with_id(privk2, 1, port),
        KeyPair::new_with_id(privk2, 2, port),
    )
}

pub fn get_local_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[test]
fn test_channel() {
    init_tracing().unwrap();
    let port = 10000;
    cleanup_storage(port);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());
    let user2 = prepare_client(port, &server.get_pkh(), &client2.privk, allow_list.clone());
    user1
        .send(Some(client2.get_identifier()), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());
    broker_server.close();
    cleanup_storage(port);
}

#[test]
fn test_ack() {
    let port = 10001;
    cleanup_storage(port);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let _ = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());
    let _ = prepare_client(port, &server.get_pkh(), &client2.privk, allow_list.clone());

    let client_config1 = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        client1.get_pkh(),
        None,
    )
    .unwrap();
    let myclient = Client::new(
        &client_config1,
        Cert::new_with_privk(&client1.privk).unwrap(),
        allow_list,
    )
    .unwrap();

    myclient
        .send_msg(
            client1.get_identifier(),
            client2.get_identifier(),
            "Hello!".to_string(),
        )
        .unwrap();
    let msg = myclient.get_msg(client2.get_identifier()).unwrap().unwrap();
    assert_eq!(msg.msg, "Hello!");
    let msg_dup = myclient.get_msg(client2.get_identifier()).unwrap().unwrap();
    assert_eq!(msg.uid, msg_dup.uid);
    assert!(myclient.ack(client2.get_identifier(), msg.uid).unwrap());
    println!("{:?}", myclient.get_msg(client2.get_identifier()).unwrap());
    assert!(myclient
        .get_msg(client2.get_identifier())
        .unwrap()
        .is_none());
    broker_server.close();
    cleanup_storage(port);
}

#[test]
fn test_reconnect() {
    let port = 10002;
    cleanup_storage(port);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let _ = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());
    let _ = prepare_client(port, &server.get_pkh(), &client2.privk, allow_list.clone());

    let client_config1 = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        client1.get_pkh(),
        None,
    )
    .unwrap();
    let myclient = Client::new(
        &client_config1,
        Cert::new_with_privk(&client1.privk).unwrap(),
        allow_list.clone(),
    )
    .unwrap();

    myclient
        .send_msg(
            client1.get_identifier(),
            client2.get_identifier(),
            "Hello!".to_string(),
        )
        .unwrap();
    let msg = myclient.get_msg(client2.get_identifier()).unwrap().unwrap();
    assert_eq!(msg.msg, "Hello!");
    myclient.ack(client2.get_identifier(), msg.uid).unwrap();
    assert!(myclient
        .get_msg(client2.get_identifier())
        .unwrap()
        .is_none());
    broker_server.close();

    // Reconnect
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    myclient
        .send_msg(
            client1.get_identifier(),
            client2.get_identifier(),
            "World!".to_string(),
        )
        .unwrap();
    let msg = myclient.get_msg(client2.get_identifier()).unwrap().unwrap();
    assert_eq!(msg.msg, "World!");
    myclient.ack(client2.get_identifier(), msg.uid).unwrap();
    broker_server.close();
    cleanup_storage(port);
}

#[test]
fn test_stress_channel() {
    let port = 10003;
    cleanup_storage(port);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());
    let user2 = prepare_client(port, &server.get_pkh(), &client2.privk, allow_list.clone());

    for i in 0..1000 {
        println!("Sending: {}", i);
        let send_ok = user1.send(Some(client2.get_identifier()), "Hello!".to_string());
        if send_ok.is_err() {
            println!("Error: {:?}", send_ok);
        }
        assert!(send_ok.is_ok());

        let mut ok = false;

        while !ok {
            let try_recv = user2.recv();
            if try_recv.is_err() {
                println!("Error: {:?}", try_recv);
            }
            assert!(try_recv.is_ok());
            let recv_ok = try_recv.unwrap();
            if recv_ok.is_none() {
                continue;
            }
            assert!(recv_ok.is_some());

            ok = true;
            let msg = recv_ok.unwrap();
            assert_eq!(msg.0, "Hello!");
            assert_eq!(msg.1, client1.get_identifier());
        }
    }
    broker_server.close();
    cleanup_storage(port);
}

#[test]
fn test_local_channel() {
    let port = 10004;
    cleanup_storage(port);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());
    let user2 = prepare_client(port, &server.get_pkh(), &client2.privk, allow_list.clone());

    user1
        .send(Some(client2.get_identifier()), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());
    broker_server.close();
    cleanup_storage(port);
}

#[test]
fn test_dinamic_allow_list() {
    let port = 10005;
    cleanup_storage(port);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![server.get_identifier(), client1.get_identifier()]);
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());
    let user2 = prepare_client(port, &server.get_pkh(), &client2.privk, allow_list.clone());

    user1
        .send(Some(client2.get_identifier()), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap_err();
    assert!(matches!(msg, BrokerError::RpcError(RpcError::Channel(_))));

    allow_list
        .lock()
        .unwrap()
        .add(client2.get_pkh(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    user1
        .send(Some(client2.get_identifier()), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();

    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());

    broker_server.close();
    cleanup_storage(port);
}

// Test with the same public key hash but different IDs
#[test]
fn test_local_service_id() {
    let port = 10006;
    cleanup_storage(port);
    let (server, client1, client2, client3) = get_keys_dif_id(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
        client3.get_identifier(),
    ]);
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let user1 = prepare_client_with_id(
        port,
        &server.get_pkh(),
        &client1.privk,
        Some(client1.id),
        allow_list.clone(),
    );
    let user2 = prepare_client_with_id(
        port,
        &server.get_pkh(),
        &client2.privk,
        Some(client2.id),
        allow_list.clone(),
    );
    user1
        .send(Some(client2.get_identifier()), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());

    broker_server.close();
    cleanup_storage(port);
}

#[test]
fn test_routing() {
    let port = 10007;
    cleanup_storage(port);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);
    let routing = RoutingTable::new();
    routing
        .lock()
        .unwrap()
        .add_route(client2.get_identifier(), client1.get_identifier());
    routing.lock().unwrap().add_route(
        client2.get_identifier(),
        Identifier {
            pubkey_hash: client1.get_pkh(),
            id: None,
            address: get_local_addr(port),
        },
    ); // Wildcard
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), routing.clone());
    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());
    let user2 = prepare_client(port, &server.get_pkh(), &client2.privk, allow_list.clone());

    // An error should occur because the routing table does not have a route for client1 to client2
    user1
        .send(Some(client2.get_identifier()), "Hello!".to_string())
        .unwrap();
    assert!(user2.recv().unwrap().is_none());

    // Now we add a route from client1 to client2, so the message should be delivered
    routing
        .lock()
        .unwrap()
        .add_route(client1.get_identifier(), client2.get_identifier());
    user1
        .send(Some(client2.get_identifier()), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());

    routing
        .lock()
        .unwrap()
        .save_to_file("routing.yaml")
        .unwrap();
    let new_route = RoutingTable::load_from_file("routing.yaml").unwrap();
    std::fs::remove_file("routing.yaml").unwrap();
    assert_eq!(*new_route.lock().unwrap(), *routing.lock().unwrap());

    broker_server.close();
    cleanup_storage(port);
}

#[test]
fn test_integration() {
    let port = 10008;
    cleanup_storage(port);
    let (server, client1, client2, client3) = get_keys_dif_id(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
        client3.get_identifier(),
    ]);
    let routing = RoutingTable::new();
    routing.lock().unwrap().add_route(
        client1.get_identifier(),
        Identifier {
            pubkey_hash: client3.get_pkh(),
            id: None,
            address: get_local_addr(port),
        }, // Wildcard (client2 and client3 have the same pubkey_hash)
    );
    routing.lock().unwrap().add_routes(
        client2.get_identifier(),
        vec![client1.get_identifier(), client3.get_identifier()],
    );
    routing
        .lock()
        .unwrap()
        .add_route(client3.get_identifier(), client1.get_identifier());
    // Not client3 to client2, so it should not be able to send messages to client2

    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), routing.clone());
    let user1 = prepare_client_with_id(
        port,
        &server.get_pkh(),
        &client1.privk,
        Some(client1.id),
        allow_list.clone(),
    );
    let user2 = prepare_client_with_id(
        port,
        &server.get_pkh(),
        &client2.privk,
        Some(client2.id),
        allow_list.clone(),
    );
    let user3 = prepare_client_with_id(
        port,
        &server.get_pkh(),
        &client3.privk,
        Some(client3.id),
        allow_list.clone(),
    );

    // user1 and user2 should be able to communicate
    user1
        .send(Some(client2.get_identifier()), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());

    // user3 and user1 should be able to communicate
    user3
        .send(
            Some(client1.get_identifier()),
            "Hello from client3!".to_string(),
        )
        .unwrap();
    let msg = user1.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello from client3!");
    assert_eq!(msg.1, client3.get_identifier());

    // user3 should not be able to send messages to user2
    user3
        .send(
            Some(client2.get_identifier()),
            "Hello from client3!".to_string(),
        )
        .unwrap();
    assert!(user2.recv().unwrap().is_none());

    broker_server.close();
    cleanup_storage(port);
}

pub fn init_tracing() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .parse("info,tarpc=off") // Include everything at "info" except `libp2p`
        .expect("Invalid filter");

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
        .try_init()?;
    Ok(())
}
