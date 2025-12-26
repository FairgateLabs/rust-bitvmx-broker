use bitvmx_broker::{
    channel::channel::{DualChannel, LocalChannel},
    identification::{
        allow_list::AllowList,
        identifier::Identifier,
        routing::{RoutingTable, WildCard},
    },
    rpc::{
        errors::{BrokerError, BrokerRpcError},
        rate_limiter::{RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_RATE},
        sync_client::SyncClient,
        sync_server::BrokerSync,
        tls_helper::Cert,
        BrokerConfig, MAX_FRAME_SIZE_KB, MAX_MSG_SIZE_KB,
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
    );
    let server = BrokerSync::new(
        &server_config,
        storage.clone(),
        server_cert,
        allow_list.clone(),
        routing,
    )
    .unwrap();
    let local = LocalChannel::new(
        Identifier {
            pubkey_hash: "local".to_string(),
            id: 0,
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
    );
    let server = BrokerSync::new(
        &server_config,
        storage.clone(),
        server_cert,
        allow_list.clone(),
        routing,
    )
    .unwrap();
    let local = LocalChannel::new(
        Identifier {
            pubkey_hash: "local".to_string(),
            id: 0,
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
    );
    let user = DualChannel::new(&server_config, client_cert, id, allow_list).unwrap();
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
            id: self.id,
        }
    }
}
fn cleanup_storage(start_port: u16, count: u16) {
    for port in start_port..start_port + count {
        let _ = fs::remove_dir_all(&PathBuf::from(format!("storage_{}.db", port)));
    }
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
        KeyPair::new(privk2, port + 1),
        KeyPair::new(privk3, port + 2),
    )
}

fn get_other_keys(port: u16) -> (KeyPair, KeyPair, KeyPair) {
    let privk1 = " b'-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+ccS2WYlbbPrL\nR+i6HqXtQ3Y1r9aAzDj0N2N7INYbQplsllFe28z8WU1ZZpiiBBsRtzFAtJjX5JBF\nz62phW/86zMwMDP36pLyIpSGcLWdATR/2tsmzOZfodxPgejGLhPBcZc613YRP4tW\niwzXBt1ZLwUcTGkz25j80qvbInhdTsTA6ebzlREjQOq0nan2g4SIc0dPe4nB8kxW\nzz7Ra/Bq8wwoMnNGpW8RxFpzJ/bsYy042/RPeXBt0fhErW3e68mEQkaXaqpZt2g0\nSsraPC8qUL1ZkWainH7tFk6QDfatE8hZ0QbYPYiP6KxCYkPjX7QMbPDm7Z2m7Dxp\nCtufwN5ZAgMBAAECggEABj1dg9j6qGFxdSQZwrFa3+N4NcmZVlZ6njvLWV8pzLJZ\nqwZgy6IZfQIjB+UV5qcKSQIOzc8s+9PcC0GC7900nl2Ja5CEv2By6JaL9byvIqIF\nuZOu3v5TJPp9aKh5uzaKxKmHWjDxiB6kHtWG+euaaH/jI7p4LvAIuu3fHhqqxWnO\n7DCuP4gBTT4Hkqjo81JgqkQSlYA9ch4qkGy8ttZFT/TK33gRYJdQEY0L80Rfhs9Z\nsBMnCYYXBjc8DCbVIdm8IEwuw1Re5wJrFqpElKn4AJsfAdM/zeD3Phb7sn4zPpdE\nGShvi9dh6BkukE7PFzTze5uQq+Vm/W5xkBCwKYWzNQKBgQD8selGNPUjsDZkpSQS\nFDwHXSsml8lZbxFPyGsjLuqyfC3xnlgKlx46zAIsLhqBfb1USGaQ/8pTUPJmgjD5\nSvznPI+cjkWFE2M4FXS2093nDP8OJ5u3xOdbT84flHze+BtfHfRAOCH3uDmYpFel\nsi2D3KEg7//12nzj06suC6TYVQKBgQDA720RYmfpuVe9+6BjEhP8intw6mLxLsVd\nadfi0Qh7VbxU1jjZ7YfmhqlK/qSgmUExvS6lXoMVzcSu5K/8M3+IeNcb832FcRdn\nGg3+dCqE9/U+atP1Id7aOfkD+eFNBjBz6c26wnPCvUP+51k6MU9vRzATJqNkwYEU\nvrbFyQ+B9QKBgQDSSBcQhndM2JGbFVW7+byugBith/hVhTjJxMVrRNqn5vCwtY0c\nWv8b/LL+IuuJwKIyJgG8PjAXPzBIn6Szf3SP1PTJWhd+E1Eo1aoHjq2FXWpOVCWg\nOqowcWvdGcsEHUFh2OJuIogZxeOgI3qQd4KqzYoEh9Pfuo7dZEJ6EdR+9QKBgFl3\nLQZgsXrqHUvVwPvvyCDVPoSPy623WIIGsLtW3y4CBcD5TYeQ4/H8A8jo6AIozth3\nt4ermfGkZ04KcajrYHoyPt2RPWWBma6PoGmcCJN8P9bfxsXnHOXo+BXl65nCAvnd\nMy8lOHTXOw6azP91GjapthtLUX1JVcf+39Y7c9t5AoGBAN2kFAVj8DqiMKQOqTf8\nJNoR5lZSt5hCQRjoBvqF/+PLwfL7QNHTv8VzaqF8jvAL0YJ8yC8fqxyhTgzCe7L6\nCsKMVsRp2jkVu1xQYkSrEvtx4LbmNt0+zXnO2SoqSMTPOkd1ru3pWN5OWgNzrt/M\nbkNbnY4Boet6PbtakbxX1gAj\n-----END PRIVATE KEY-----\n'";
    let privk2 = " b'-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCx/RjVZkIOsX14\nN3LQP5A9twNwxJ6ADLZX44cQl8xbf5QAEIESWy+J+evaxZ+RF7llao+Vn+N2bVCQ\nqemxYkuAoyU6zLnlJ15Fn65s0chi1LmhQU21RSNImhMyAJ/NqKHTBpsUB+adpgXX\nC7kvmzDv+5gaNOiozDsasB51Dcwov8QG2UHUXDSrnsxN7BWjWmmaGSrppNPkYVAH\nyU5WTxg7YTnIeC2XMoQOUV2DmhDNjJP4FG9IUmNtG+lnVWjyOIEKDezzKOi0PZue\nJFgdpuU1TEieMdEEcZwVVVRetT4YJ/vgSM8aYwmFDFQ2ut/WdCQJrgSr6AldyXXX\nTtV/jOeBAgMBAAECggEAQFX1CQXqcLc1XCPmy2F+eOBTTQq1JCH0MzaaFqRYCObH\nj3JnxUPSnjQJTc3LTL3flMn81p+xr5f53CCeyTB3jCrshSGFPFCLoe0DNnBp11d/\nNcuOFCzGgTK4J4XUPZlrzQSBP69Pa8KcL8wcBxo4iTZPF4HyazlPT+lDSRpQppV3\nU07WQyC4CNTlnKDKIxuUebINH/MUxacmb0CQxw3/qSo+OgNuO2/X6met653h3A+k\nCuhdcIjeMfcees6SGOvFA9c/BdS8jM3oCghX+/0QP6B7UibbzKRzDKbM+Ed214rZ\nJycJE4cVVf/b1C8yqtv/wNQHknMKxHWgQ8sB9Ac5dQKBgQDtAkXlGQY2RxfSsnRM\nWfLK6vQF3qQtCS56fcLGfuiq7svL1y7Z78bvHMNGMp8xStufoazp6P/uiOM8Sw0B\nW0Mrdd+u9nnqC9yHDh5gtx/Rj2dYPJsiJApSBe889dPyK74tKWSxCJUEgTGxfL6h\nAW5MhhVhSjQ3xvZ0prfWs2MGWwKBgQDAQCa3XjQ10HcgqvigV1v5iHvcELeRrZAN\nQ9YCGgwmnFlZy8p215AzsP1HGbHsNYEcrw7kNouKYIRGbQ004RrE971us+y1LVcI\nIrLUi5gYQUlrl6cRDND7cLb71IKYm5fj+2SKtsy+8YjaNSjsBQ0phGX2FIZtnymq\npStq1O0IUwKBgQCjajTNEKMC26PmZ5reZgqMtNFKFse2MaV1Wa7pc+lyqjGkO5sX\nM0dD6N4PUaoHr6iceTojEb8dNg8PrGOsMsOufJidJ17J7CHCkQ6K+tiagjjsUuVX\n9eeTxHm+23SmflijBO5jThqJP5cG3I8HrlfhtXWaXjKA3tNhfO42v/sgDwKBgQCJ\n9f9Sm2GwNJcodEjTF53DJjRsKfrxqbG0MzgCbhrGInDkRaBXRD4ROjOnsELEFWk/\n4kg3cQUWGkkSGPPfPKLvMjFYnfmB0rWf+vaGHF7bGQ7NDRkw3RejOLG3ajsFtLJ9\nQkxWVvP7Gm1w2bEyHjXh00cwHm6RgCRwdvL/SSmITQKBgQDVPjUtAdnNeeM2vUB7\nVZSV2UB3OP93WlYcK0buIkurq7TIij9Jc4/o9hscDEYNJSNM1XZlyK9WO5jYVX81\nj8SsWON7G2SBTjZrrhcNgUzMp5iNZawUmGPZOBMPFnabcOnOE4mrKFgbaoIFhHjY\nI/5QSHVeDsrihZkZqzZ6qeMx2g==\n-----END PRIVATE KEY-----\n'";
    let privk3 = " b'-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC1ghQFCdzD0rFd\nYWNMZM/R5QBsDWx0WmmOff/jXRwvJHiiL49sQQNukg9tyRZAG8Iyh52FclKhV38R\nxJYRANwU8ISqv3XZ1nUUhMWXX36s/ldONFFKAm4QsjmurIgiiqWZsSA18xwVzAOs\nZeUt9mabGogxQWsp7+chnIm9nkbyve9AHU2+5rSePDknT+/e8aKBOgnnkVQMK6NL\ndMZACGtyY7ZyQNbrCYXzwJ/Uw+hli+YAKKkZXcV8U794ifkhaMLP+9j9O/e4qJMh\n+Us9MrawZJ1IAhNPmYg+mpNNeqCyAozNkfI463QnyPTvVdAtZNnCSkwOH12FKnMi\nV6rJdZbhAgMBAAECggEADs5Xl7mgOpEbSsTA9uBaW4LUr/vAVxVw+uCoWQGlZOsS\ntBgxGOGMyB4+B/SZTg11n+2UGeijeOnMQcTJgQWS7lpYWB1aHbTyxAO4oop1qOLu\neECoSOM92zrOncMRL9Ajhg/+0qfMKLMFsbB2K3OoFwrpBSuS9E7PidxdGAyrOO3G\nRJFr0h5YTjwKRYsNRBMowvvwb/tT5s8lK+sxxq4y/6rixFcD7rBBV7Zu3G+TX2OL\nhZTnNdNct7QQuie4+qNspbedDPk0IPrKwgffBoEJ7fe2jAZv4vZM0TL4dE7O+EL1\nL6pO8SXrRI1loevcTSfTdrV/8fL9pF1csTbfSdK1iQKBgQDamog3viubhJ9GGoVt\nMTyYECr5Dq8SAzxJNARhLsYLyE5KMBRPt8oEiV1hsGsiVeZjprCmsWNi3eaBvthp\n+3kS+rIZAjHycBOjgY5jBm5XHZsF0VC36TmbVi1nM5MUBEp8KQtkynuYJCffOver\nXr4xO0qFMX20CvM9vCqtSfOVNwKBgQDUjv60Vj9vdYnFSme68Fgyd7q3yFOP/LjD\nMuiCF61d8mXBV3IkSAWPyHJxbzhQ4pbofB47jCcVwhzFhTBOxZHdLLdG5WHjFX2t\nBnsjSaGWTp1R8gAum2x7cQIde4gx1cFhouvyTk/Z+vpWACXqJVGtrGZp5KGufQpu\npLxu9IrApwKBgQDQ516HjqeTrhCbaNrbN3NFiiXW7q5lU0w4VIpe6NkAB4KxqPKw\nH93hqffgVDx9ioNp9bDZC6oDoDUZBm1AEr5oYcTy20MqAOrzlOqiPVIS1EsCKz6t\nEicoCBnJhuLl/RfFQWAPCOVFxj+IN4zZaufsmlGjqWEMPm6nL3vFMGejzwKBgQCN\nXt3Ai2x9cStEcIw1JQ1D46Xn/fC131vzV7SUcbL4vPM4eDSONOieDK8xCsvl4A6G\naaah7EFCk2wXYtISUg0FkWwEVyOXqP+BSMI1Yg96rKatjcrZNL4eC7dgbHzUyFpp\n2bYb3kH1tJsy/7430MJWREeJPmraZoe9twsssLBoGQKBgQCMbl5kHgEN1uNz60zb\n0zjaMn1jpxGWjQS2bUGVQPmtRJlTALMZSQIit/AXbspBpuXQpLAeWS0YTaoyb282\nRNeBt95Qawee31hQCTF2AbgrQHIvInq6h6D1tZqfkNz8XutEzSkmt7p/XL4X1SG6\nz2m+VDJ/3ZgsQM2IA6uI83hWKw==\n-----END PRIVATE KEY-----\n'";

    (
        KeyPair::new(privk1, port),
        KeyPair::new(privk2, port + 1),
        KeyPair::new(privk3, port + 2),
    )
}

fn get_keys_dif_id(port: u16) -> (KeyPair, KeyPair, KeyPair, KeyPair) {
    let privk1 = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzkbFynswfys/\nVNbM4hzYNKCdAuxYI/jysOPkRHGhlJe+71EE9F2CpAZnjevBsUWxi3+LatfMZjwi\nUz/l3iC6ow8Dsar0BO6RmWQR8Uf/1sx+WNjBk2woISPb60oXbXYj8AVUqYUUSo/Q\nRF5kuGT7dsMvUAx8Irn93w4A5VXx+FLn3r38Tymv7qOMT5cO1xrNStsluBD1RdPj\nz+B6b+7woAKqkrNFR+ZH0HUUKldA+A+pGElQLODyLB7OwxHgKtEsFdyiiDuKW2mP\nsk2dsab9HCNdo9cViA9UbeykDXq7h0/7gYg9XBH8LqqXYpSk/LE6T8k1RVa9EBxV\nRpYqlvFPAgMBAAECggEAV64pfRQq0aIPwP/IiLYkTS/iThWcgH03ZcWaOED7fqqc\nYd+7rhjVVq0qb3uEWCnlzhNE63YJZa0tHIcHANNIEjDO27hZkXd4y8CsQutV8doO\nfeEyCbic/tgffH3Yv1AZ18qTx1QsAL0TKuPhY2rWi26KTAzhTDKP1iyO23ox7Uqs\nwWChuHWyw7SmECRmjKOjTLs1Axea3fos6ERgEv/KZiTi+a9he5JuHOXO6aKTvHI7\nlTAMdloy1CnK6G3Ql7LfBeX20hIwDSZNgp5naB6NjJiDTbxxlGj7apW6hquzJpRP\n1Tn2YLvVKl5bdAOHh44wHBhZR9COjxUT+uASYRb5wQKBgQD7FTe3VPrsi6ejo7db\n9SwTUjsTQKoxrfoNc0xPzGGwKyyArGM++NQI1CZuQQDXVoYl+JC1JOcTLjjW/TYu\nwVGAr63bjtYjU0e8NZzum3nIZ7rpyHJpnbCLBc678KNCvblD4u/Vl1bx/9vRiCTx\n9S0r/LJ54Jr3Ohx9feYERc4K/QKBgQDmOlWNHwFlC2pkYI/0biXWybQZWvz+C5x3\nJO6tf0ykRk2sBEcp07JMhJsE+r4B+lHNSWalkX409Fn6x2ch/6tLP0X+viM5nr+2\nRpGHLpUBeq4+RKMmUS/NgY2DoRV1DRnfk4Vt0BZy5Voc4OVQz0zohwFzYhY60ThR\nV3UJ9HbdOwKBgQCcBS8+CNxzqMRe9xi1V8AvsWVsLT6U6Fr9iKve2k3JvspEmtqB\nAvYfFlVbJaF0Lhvl9HNXXLsKPCqtzWKh4xbWNFSAnl2KTfHBjj8aNhqS4YJQS3Jt\nFsPhX5Z7SqjojCRXfukxfH1Wm3ro1QTAJW4Qa1IsUdl5zu5tPJJ2DTpfsQKBgCii\nXR0mPsnFxQZoYKAEnNsXCJl9DLAN/pSsyQ+IK0/HNMhKjQDd41dMBExRsR2KP8va\ny6onTr4r7oGrlhFTHbmPNlxq1K7DzRRvyhmw6A21yHEnDiCiLay40/BKiw34vPtP\n/znNg1jOECSOsQqdO/bCdUgXJNNGwAjjRb33Ds+nAoGAW76wLk1lwD2tZ8KgMRUU\ni0BkY7eDXPskxCP6BjFq10J/1dC/dsLO9mZfwl2BJ2D+gGmcIzdSb5p1LkuniGuv\nV+/lSa8bdUKwtd5l+CZ0OMqmHryQZICqGeG5uREYv5eqs4mDiuM8QkZdOZUKWzPc\nwWJXrp5cQtvgjS/HyjHB69o=\n-----END PRIVATE KEY-----\n'";
    let privk2 = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCeJYILLK2EpGP9\nCrlEeHL1hYODftAUxJTacRezNNuyAqqP04H0IFffXhdz/f54HnYnaN1VrMGNQlR5\nBashFjZa7fVEFp3osVgNEPNu63MA1Gr7o4BakopRbMx7jUyhmlJXNP3VX5tZEha+\nV7GOZEeh2Ej3pehnE/E6SD16Ez9aaGydFgrMALHjT2NfucK0XCcDvMbq53PsBaLm\nnH5TLnvtZvYmdyDoUe+RvlwaRAHv4AWDOElhQrj970giHWY6i9QgqrlTIYN5cQrD\nM6kNj1SaBtCNpG/wIK3NMLW7PAYeEKTopwdsFuVL+1e0IAsTIVpDC1mb3r2GlPji\n0GaMLBAHAgMBAAECggEAFPHDvMYgfuIkqeULL1HCa9jQV5Bqb22vhxSWPnIgLH2k\n6CJrYhEMgjUcZwy68F6caFC/i3KzOYmQ1WxWQy4Fadp88pUKOcCO+EAH9WcyVmhL\neOMpAxXIQstlc3F9tiNRh2IpweIFGXFHWNMVXVXTlNAnrcCnvEsMVhsuJSY6bDcV\n5ejQKE8kM8F30FzD2mii36XamsreMpQBAIlm0i1HH/8PpynUQ12bb2M0T/FR9C5V\nAbfeLUOgrzWgBs9hxmlBzILusJFjv7OvwIkF97GgoAyLKqFmxzncwQUTqh9iH2Js\nemN6Qg+vPIg2Et8Ku9XEX+CSXvDwFckB2Z14jqQw8QKBgQDPHDzAFDSTl+aPH+vd\n01wxtaFyP7KP2OaRabW1qzTPww87agbN3wPJqBBf9lEjVeGNjLrp2NyHX6Wfnt5V\nlpeWts13/M43rju2JJwOrfZnwJsJgQ9ZEQw30e1LWeiGpr0kcWlv2059tEiKgBwY\nNlw6evsCyFjrIuSqgg3riO9xMQKBgQDDel5TfTJ3BJZlgFYnU1YxUZDQ1mcMDnSK\ntdRLdpVWTEkjzf0a6rGJYla0NoqQdH9qDfimVMY6+RQLZVdhhXDVnQuwV0CK9ERY\nQWy/PEoPvIagTXgKJ8fKLYcG420fJJtPmTSEoPZg1PXtuABNj/68bI7ONL5CY6gO\n8iFJU0sGtwKBgA6mlLWRuFZofGrLe0fp16+8hXsrflomocjPjYcYYVgBGGa/jVOq\n3v244c+oAP1a6eW1etNn/9GjtnegKWIskPScYdSHEZ9mt9qepFt1euTD/zOg6ZEH\nX7HjK8IUzhoYWXDmhOrgvKCvzCHgBhzAW63XXUJJIeEgSsS1Bn8O5MFBAoGAMuiv\noDa+6dg8AvtFdMBzdiyz9m+gLrelCmsIew7LHcqIUdbX0CbHTexagFykAbMVa91v\noIH7jmhIHB+sfi1ukXNxE9/lY0rycbm4RKXC9A45UY5bcOmjUrhArj6UsMOr3zMb\nRl9VSyqrUdnV2l1iDliHaJS76DZkEmBk4t/abkkCgYEAxkk3skKgRJPt2bFLzdHV\n3Au24P/Cyqf1LIfXpuJcMBfAhw55g6DOLR4O0BH+s7cZk8hrGVeI9WyhC5EgzZrF\nBjTlZFqFtsz5psj1oNqgr/JnO2fL3csxbDR81q9uSSzdlN7BlzBpdQahi53K9MHi\nZDNGUy5a/PopNnWSzfHYUas=\n-----END PRIVATE KEY-----\n'";

    (
        KeyPair::new(privk1, port),
        KeyPair::new_with_id(privk2, 0, port + 1),
        KeyPair::new_with_id(privk2, 1, port + 2),
        KeyPair::new_with_id(privk2, 2, port + 3),
    )
}

pub fn get_local_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[test]
fn test_channel() {
    init_tracing().unwrap();
    let port = 10050;
    cleanup_storage(port, 3);
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
        .send(&client2.get_identifier(), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());
    broker_server.close();
    cleanup_storage(port, 3);
}

#[test]
fn test_ack() {
    let port = 10003;
    cleanup_storage(port, 3);
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
    );
    let myclient1 = SyncClient::new(
        &client_config1,
        Cert::new_with_privk(&client1.privk).unwrap(),
        allow_list.clone(),
    )
    .unwrap();

    let client_config2 = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        client2.get_pkh(),
    );
    let myclient2 = SyncClient::new(
        &client_config2,
        Cert::new_with_privk(&client2.privk).unwrap(),
        allow_list,
    )
    .unwrap();

    myclient1
        .send_msg(client1.id, client2.get_identifier(), "Hello!".to_string())
        .unwrap();
    let msg = myclient2
        .get_msg(client2.get_identifier().id)
        .unwrap()
        .unwrap();
    assert_eq!(msg.msg, "Hello!");
    let msg_dup = myclient2
        .get_msg(client2.get_identifier().id)
        .unwrap()
        .unwrap();
    assert_eq!(msg.uid, msg_dup.uid);
    assert!(myclient2.ack(client2.get_identifier().id, msg.uid).unwrap());
    println!(
        "{:?}",
        myclient2.get_msg(client2.get_identifier().id).unwrap()
    );
    assert!(myclient2
        .get_msg(client2.get_identifier().id)
        .unwrap()
        .is_none());
    broker_server.close();
    cleanup_storage(port, 3);
}

#[test]
fn test_reconnect() {
    let port = 10006;
    cleanup_storage(port, 3);
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
    );
    let myclient1 = SyncClient::new(
        &client_config1,
        Cert::new_with_privk(&client1.privk).unwrap(),
        allow_list.clone(),
    )
    .unwrap();

    let client_config2 = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        client2.get_pkh(),
    );
    let myclient2 = SyncClient::new(
        &client_config2,
        Cert::new_with_privk(&client2.privk).unwrap(),
        allow_list.clone(),
    )
    .unwrap();

    myclient1
        .send_msg(client1.id, client2.get_identifier(), "Hello!".to_string())
        .unwrap();
    let msg = myclient2
        .get_msg(client2.get_identifier().id)
        .unwrap()
        .unwrap();
    assert_eq!(msg.msg, "Hello!");
    myclient2.ack(client2.get_identifier().id, msg.uid).unwrap();
    assert!(myclient2
        .get_msg(client2.get_identifier().id)
        .unwrap()
        .is_none());
    broker_server.close();

    // Reconnect
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    myclient1
        .send_msg(client1.id, client2.get_identifier(), "World!".to_string())
        .unwrap();
    let msg = myclient2
        .get_msg(client2.get_identifier().id)
        .unwrap()
        .unwrap();
    assert_eq!(msg.msg, "World!");
    myclient2.ack(client2.get_identifier().id, msg.uid).unwrap();
    broker_server.close();
    cleanup_storage(port, 3);
}

#[test]
fn test_stress_channel() {
    let port = 10009;
    cleanup_storage(port, 3);
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
        let send_ok = user1.send(&client2.get_identifier(), "Hello!".to_string());
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
    cleanup_storage(port, 3);
}

#[test]
fn test_dinamic_allow_list() {
    let port = 10012;
    cleanup_storage(port, 3);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![server.get_identifier(), client1.get_identifier()]);
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());
    let user2 = prepare_client(port, &server.get_pkh(), &client2.privk, allow_list.clone());

    user1
        .send(&client2.get_identifier(), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap_err();
    assert!(matches!(msg, BrokerError::RpcError(RpcError::Channel(_))));

    allow_list
        .lock()
        .unwrap()
        .add(client2.get_pkh(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    user1
        .send(&client2.get_identifier(), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();

    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());

    broker_server.close();
    cleanup_storage(port, 3);
}

// Test with the same public key hash but different IDs
#[test]
fn test_local_service_id() {
    let port = 10015;
    cleanup_storage(port, 3);
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
        .send(&client2.get_identifier(), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());

    broker_server.close();
    cleanup_storage(port, 3);
}

#[test]
fn test_routing() {
    let port = 10018;
    cleanup_storage(port, 3);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);
    let routing = RoutingTable::new();
    routing.lock().unwrap().add_route(
        client2.get_identifier(),
        client1.get_identifier(),
        WildCard::No,
    );
    routing.lock().unwrap().add_route(
        client2.get_identifier(),
        client1.get_identifier(),
        WildCard::To,
    ); // Wildcard
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), routing.clone());
    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());
    let user2 = prepare_client(port, &server.get_pkh(), &client2.privk, allow_list.clone());

    // An error should occur because the routing table does not have a route for client1 to client2
    user1
        .send(&client2.get_identifier(), "Hello!".to_string())
        .unwrap();
    assert!(user2.recv().unwrap().is_none());

    // Now we add a route from client1 to client2, so the message should be delivered
    routing.lock().unwrap().add_route(
        client1.get_identifier(),
        client2.get_identifier(),
        WildCard::No,
    );
    user1
        .send(&client2.get_identifier(), "Hello!".to_string())
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
    cleanup_storage(port, 3);
}

#[test]
fn test_integration() {
    let port = 10021;
    cleanup_storage(port, 4);
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
        client3.get_identifier(),
        WildCard::To, // Wildcard (client2 and client3 have the same pubkey_hash)
    );
    routing.lock().unwrap().add_routes(
        client2.get_identifier(),
        vec![client1.get_identifier(), client3.get_identifier()],
    );
    routing.lock().unwrap().add_route(
        client3.get_identifier(),
        client1.get_identifier(),
        WildCard::No,
    );
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
        .send(&client2.get_identifier(), "Hello!".to_string())
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1.get_identifier());

    // user3 and user1 should be able to communicate
    user3
        .send(&client1.get_identifier(), "Hello from client3!".to_string())
        .unwrap();
    let msg = user1.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello from client3!");
    assert_eq!(msg.1, client3.get_identifier());

    // user3 should not be able to send messages to user2
    user3
        .send(&client2.get_identifier(), "Hello from client3!".to_string())
        .unwrap();
    assert!(user2.recv().unwrap().is_none());

    broker_server.close();
    cleanup_storage(port, 4);
}

#[test]
fn test_simple_channel() {
    let port = 10025;
    cleanup_storage(port, 3);
    let (server, _, _) = get_keys(port);

    let allow_list = AllowList::new();
    allow_list.lock().unwrap().allow_all();
    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());

    let (server_config, _, _) = BrokerConfig::new_only_address(server.port, None).unwrap();
    let (user1, client1) = DualChannel::new_simple(&server_config, 0).unwrap();
    let (server_config, _, _) = BrokerConfig::new_only_address(server.port, None).unwrap();
    let (user2, client2) = DualChannel::new_simple(&server_config, 0).unwrap();

    user1.send(&client2, "Hello!".to_string()).unwrap();
    let msg = user2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client1);
    broker_server.close();
    cleanup_storage(port, 3);
}

#[test]
fn test_multiple_servers() {
    let port = 10028;
    cleanup_storage(port, 6);

    let (server, client11, client12) = get_keys(port);
    let (server2, client21, client22) = get_other_keys(port + 3);
    let allow_list = AllowList::new();
    allow_list.lock().unwrap().allow_all();

    let (mut broker_server1, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let (mut broker_server2, _) =
        prepare_server(port + 3, &server2.privk, allow_list.clone(), route_all());

    let user1 = prepare_client(port, &server.get_pkh(), &client11.privk, allow_list.clone());
    let user2 = prepare_client(port, &server.get_pkh(), &client12.privk, allow_list.clone());
    let user3 = prepare_client(
        port + 3,
        &server2.get_pkh(),
        &client21.privk,
        allow_list.clone(),
    );
    let user4 = prepare_client(port + 3, &server2.get_pkh(), &client22.privk, allow_list);
    user1
        .send(&client12.get_identifier(), "Hello!".to_string())
        .unwrap();
    user3
        .send(
            &client22.get_identifier(),
            "Hello from server2!".to_string(),
        )
        .unwrap();
    let msg = user2.recv().unwrap().unwrap();
    let msg2 = user4.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, client11.get_identifier());
    assert_eq!(msg2.0, "Hello from server2!");
    assert_eq!(msg2.1, client21.get_identifier());
    broker_server1.close();
    broker_server2.close();
    cleanup_storage(port, 6);
}

#[test]
fn test_local_channel() {
    let port = 10034;
    cleanup_storage(port, 3);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);
    let (mut broker_server, local_channel) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());
    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());

    local_channel
        .send(&client1.get_identifier(), "Hello!".to_string())
        .unwrap();
    let msg = user1.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(
        msg.1,
        Identifier {
            pubkey_hash: "local".to_string(),
            id: 0,
        }
    );
    broker_server.close();
    cleanup_storage(port, 3);
}

#[test]
fn test_ca() {
    let ca_key1  = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzkbFynswfys/\nVNbM4hzYNKCdAuxYI/jysOPkRHGhlJe+71EE9F2CpAZnjevBsUWxi3+LatfMZjwi\nUz/l3iC6ow8Dsar0BO6RmWQR8Uf/1sx+WNjBk2woISPb60oXbXYj8AVUqYUUSo/Q\nRF5kuGT7dsMvUAx8Irn93w4A5VXx+FLn3r38Tymv7qOMT5cO1xrNStsluBD1RdPj\nz+B6b+7woAKqkrNFR+ZH0HUUKldA+A+pGElQLODyLB7OwxHgKtEsFdyiiDuKW2mP\nsk2dsab9HCNdo9cViA9UbeykDXq7h0/7gYg9XBH8LqqXYpSk/LE6T8k1RVa9EBxV\nRpYqlvFPAgMBAAECggEAV64pfRQq0aIPwP/IiLYkTS/iThWcgH03ZcWaOED7fqqc\nYd+7rhjVVq0qb3uEWCnlzhNE63YJZa0tHIcHANNIEjDO27hZkXd4y8CsQutV8doO\nfeEyCbic/tgffH3Yv1AZ18qTx1QsAL0TKuPhY2rWi26KTAzhTDKP1iyO23ox7Uqs\nwWChuHWyw7SmECRmjKOjTLs1Axea3fos6ERgEv/KZiTi+a9he5JuHOXO6aKTvHI7\nlTAMdloy1CnK6G3Ql7LfBeX20hIwDSZNgp5naB6NjJiDTbxxlGj7apW6hquzJpRP\n1Tn2YLvVKl5bdAOHh44wHBhZR9COjxUT+uASYRb5wQKBgQD7FTe3VPrsi6ejo7db\n9SwTUjsTQKoxrfoNc0xPzGGwKyyArGM++NQI1CZuQQDXVoYl+JC1JOcTLjjW/TYu\nwVGAr63bjtYjU0e8NZzum3nIZ7rpyHJpnbCLBc678KNCvblD4u/Vl1bx/9vRiCTx\n9S0r/LJ54Jr3Ohx9feYERc4K/QKBgQDmOlWNHwFlC2pkYI/0biXWybQZWvz+C5x3\nJO6tf0ykRk2sBEcp07JMhJsE+r4B+lHNSWalkX409Fn6x2ch/6tLP0X+viM5nr+2\nRpGHLpUBeq4+RKMmUS/NgY2DoRV1DRnfk4Vt0BZy5Voc4OVQz0zohwFzYhY60ThR\nV3UJ9HbdOwKBgQCcBS8+CNxzqMRe9xi1V8AvsWVsLT6U6Fr9iKve2k3JvspEmtqB\nAvYfFlVbJaF0Lhvl9HNXXLsKPCqtzWKh4xbWNFSAnl2KTfHBjj8aNhqS4YJQS3Jt\nFsPhX5Z7SqjojCRXfukxfH1Wm3ro1QTAJW4Qa1IsUdl5zu5tPJJ2DTpfsQKBgCii\nXR0mPsnFxQZoYKAEnNsXCJl9DLAN/pSsyQ+IK0/HNMhKjQDd41dMBExRsR2KP8va\ny6onTr4r7oGrlhFTHbmPNlxq1K7DzRRvyhmw6A21yHEnDiCiLay40/BKiw34vPtP\n/znNg1jOECSOsQqdO/bCdUgXJNNGwAjjRb33Ds+nAoGAW76wLk1lwD2tZ8KgMRUU\ni0BkY7eDXPskxCP6BjFq10J/1dC/dsLO9mZfwl2BJ2D+gGmcIzdSb5p1LkuniGuv\nV+/lSa8bdUKwtd5l+CZ0OMqmHryQZICqGeG5uREYv5eqs4mDiuM8QkZdOZUKWzPc\nwWJXrp5cQtvgjS/HyjHB69o=\n-----END PRIVATE KEY-----\n'";
    let ca_key2 = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCeJYILLK2EpGP9\nCrlEeHL1hYODftAUxJTacRezNNuyAqqP04H0IFffXhdz/f54HnYnaN1VrMGNQlR5\nBashFjZa7fVEFp3osVgNEPNu63MA1Gr7o4BakopRbMx7jUyhmlJXNP3VX5tZEha+\nV7GOZEeh2Ej3pehnE/E6SD16Ez9aaGydFgrMALHjT2NfucK0XCcDvMbq53PsBaLm\nnH5TLnvtZvYmdyDoUe+RvlwaRAHv4AWDOElhQrj970giHWY6i9QgqrlTIYN5cQrD\nM6kNj1SaBtCNpG/wIK3NMLW7PAYeEKTopwdsFuVL+1e0IAsTIVpDC1mb3r2GlPji\n0GaMLBAHAgMBAAECggEAFPHDvMYgfuIkqeULL1HCa9jQV5Bqb22vhxSWPnIgLH2k\n6CJrYhEMgjUcZwy68F6caFC/i3KzOYmQ1WxWQy4Fadp88pUKOcCO+EAH9WcyVmhL\neOMpAxXIQstlc3F9tiNRh2IpweIFGXFHWNMVXVXTlNAnrcCnvEsMVhsuJSY6bDcV\n5ejQKE8kM8F30FzD2mii36XamsreMpQBAIlm0i1HH/8PpynUQ12bb2M0T/FR9C5V\nAbfeLUOgrzWgBs9hxmlBzILusJFjv7OvwIkF97GgoAyLKqFmxzncwQUTqh9iH2Js\nemN6Qg+vPIg2Et8Ku9XEX+CSXvDwFckB2Z14jqQw8QKBgQDPHDzAFDSTl+aPH+vd\n01wxtaFyP7KP2OaRabW1qzTPww87agbN3wPJqBBf9lEjVeGNjLrp2NyHX6Wfnt5V\nlpeWts13/M43rju2JJwOrfZnwJsJgQ9ZEQw30e1LWeiGpr0kcWlv2059tEiKgBwY\nNlw6evsCyFjrIuSqgg3riO9xMQKBgQDDel5TfTJ3BJZlgFYnU1YxUZDQ1mcMDnSK\ntdRLdpVWTEkjzf0a6rGJYla0NoqQdH9qDfimVMY6+RQLZVdhhXDVnQuwV0CK9ERY\nQWy/PEoPvIagTXgKJ8fKLYcG420fJJtPmTSEoPZg1PXtuABNj/68bI7ONL5CY6gO\n8iFJU0sGtwKBgA6mlLWRuFZofGrLe0fp16+8hXsrflomocjPjYcYYVgBGGa/jVOq\n3v244c+oAP1a6eW1etNn/9GjtnegKWIskPScYdSHEZ9mt9qepFt1euTD/zOg6ZEH\nX7HjK8IUzhoYWXDmhOrgvKCvzCHgBhzAW63XXUJJIeEgSsS1Bn8O5MFBAoGAMuiv\noDa+6dg8AvtFdMBzdiyz9m+gLrelCmsIew7LHcqIUdbX0CbHTexagFykAbMVa91v\noIH7jmhIHB+sfi1ukXNxE9/lY0rycbm4RKXC9A45UY5bcOmjUrhArj6UsMOr3zMb\nRl9VSyqrUdnV2l1iDliHaJS76DZkEmBk4t/abkkCgYEAxkk3skKgRJPt2bFLzdHV\n3Au24P/Cyqf1LIfXpuJcMBfAhw55g6DOLR4O0BH+s7cZk8hrGVeI9WyhC5EgzZrF\nBjTlZFqFtsz5psj1oNqgr/JnO2fL3csxbDR81q9uSSzdlN7BlzBpdQahi53K9MHi\nZDNGUy5a/PopNnWSzfHYUas=\n-----END PRIVATE KEY-----\n'";

    let port = 10040;
    cleanup_storage(port, 3);
    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![server.get_identifier(), client1.get_identifier()]);

    // Clients
    let client_cert1 = Cert::new_with_privk_and_ca(&client1.privk, ca_key1).unwrap();
    let client_cert2 = Cert::new_with_privk_and_ca(&client2.privk, ca_key2).unwrap();
    let client_config1 = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        client1.get_pkh(),
    );
    let client_config2 = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        client2.get_pkh(),
    );
    let myclient1 = SyncClient::new(&client_config1, client_cert1, allow_list.clone()).unwrap();
    let myclient2 = SyncClient::new(&client_config2, client_cert2, allow_list.clone()).unwrap();

    //Server
    let storage = Arc::new(Mutex::new(MemStorage::new()));
    let server_cert = Cert::new_with_privk_and_ca(&server.privk, ca_key1).unwrap();
    let server_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server.get_pkh().to_string(),
    );
    let mut broker_server = BrokerSync::new(
        &server_config,
        storage.clone(),
        server_cert,
        allow_list.clone(),
        route_all(),
    )
    .unwrap();

    myclient1
        .send_msg(client1.id, server.get_identifier(), "Hello!".to_string())
        .unwrap();

    myclient2
        .send_msg(client2.id, server.get_identifier(), "Hello!".to_string())
        .unwrap_err(); // Should fail because of different CAs

    broker_server.close();
    cleanup_storage(port, 3);
}

#[test]
fn test_send_message_too_large_client_side() {
    let port = 10060;
    cleanup_storage(port, 3);

    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);

    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());

    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());

    // Oversized message
    let big_msg = "A".repeat(MAX_MSG_SIZE_KB * 1024 + 1);
    let limit_msg = "B".repeat(MAX_MSG_SIZE_KB * 1024);
    let over_frame_limit_msg = "C".repeat(MAX_FRAME_SIZE_KB * 1024 + 1);

    assert!(matches!(
        user1.send(&client2.get_identifier(), big_msg),
        Err(BrokerError::MessageTooLarge(_))
    ));
    assert!(user1.send(&client2.get_identifier(), limit_msg).is_ok());
    assert!(matches!(
        user1.send(&client2.get_identifier(), over_frame_limit_msg),
        Err(BrokerError::MessageTooLarge(_))
    ));
    broker_server.close();
    cleanup_storage(port, 3);
}

#[test]
fn test_rate_limit_enforced() {
    let port = 10070;
    cleanup_storage(port, 3);

    let (server, client1, client2) = get_keys(port);
    let allow_list = create_allow_list(vec![
        server.get_identifier(),
        client1.get_identifier(),
        client2.get_identifier(),
    ]);

    let (mut broker_server, _) =
        prepare_server(port, &server.privk, allow_list.clone(), route_all());

    let user1 = prepare_client(port, &server.get_pkh(), &client1.privk, allow_list.clone());

    let mut saw_rate_limit = false;

    // Every time a client wants to send, it also needs to do a ping, so 2 tokens are consumed per request, so it should never exceed the rate limit capacity
    for i in 0..(RATE_LIMIT_CAPACITY * 2) {
        let res = user1.send(&client2.get_identifier(), format!("msg-{i}"));
        if matches!(
            res,
            Err(BrokerError::BrokerRpcError(
                BrokerRpcError::RateLimitExceeded
            ))
        ) {
            saw_rate_limit = true;
            break;
        }
    }

    assert!(
        saw_rate_limit,
        "rate limiter never triggered after many requests"
    );

    // Wait for some time to allow the rate limiter to refill
    std::thread::sleep(std::time::Duration::from_secs_f64(
        (1.0 / RATE_LIMIT_REFILL_RATE) * 2.0,
    ));
    // Now the request should succeed again
    let res = user1.send(&client2.get_identifier(), "after wait".to_string());
    assert!(
        res.is_ok(),
        "request after wait unexpectedly failed: {:?}",
        res
    );

    broker_server.close();
    cleanup_storage(port, 3);
}

#[test]
fn test_readme_example() {
    let port = 10000;
    cleanup_storage(port, 3);
    let storage = {
        #[cfg(not(feature = "storagebackend"))]
        {
            Arc::new(Mutex::new(MemStorage::new()))
        }

        #[cfg(feature = "storagebackend")]
        {
            let storage_path = format!("storage_{}.db", port);
            let config = StorageConfig::new(storage_path.clone(), None);
            let broker_backend = Storage::new(&config)
                .map_err(|e| BrokerError::StorageError(e.to_string()))
                .unwrap();
            let broker_backend = Arc::new(Mutex::new(broker_backend));
            Arc::new(Mutex::new(BrokerStorage::new(broker_backend)))
        }
    };
    // Create Server
    let server_cert = Cert::new().unwrap();
    let server_pubkey_hash = server_cert.get_pubk_hash().unwrap();

    let allow_list = AllowList::new();
    let routing_table = RoutingTable::new();

    let config = BrokerConfig::new(
        10000,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_pubkey_hash,
    );
    let _server = BrokerSync::new(
        &config,
        storage.clone(),
        server_cert.clone(),
        allow_list.clone(),
        routing_table.clone(),
    );

    // Create Client
    let client1_cert = Cert::new().unwrap();
    let client2_cert = Cert::new().unwrap();
    let client1_identifier = Identifier::new(client1_cert.get_pubk_hash().unwrap(), 0);
    let client2_identifier = Identifier::new(client2_cert.get_pubk_hash().unwrap(), 0);

    // Add clients to allow list
    allow_list
        .lock()
        .unwrap()
        .add_by_certs(
            vec![
                server_cert.clone(),
                client1_cert.clone(),
                client2_cert.clone(),
            ],
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST); 3],
        )
        .unwrap();
    // Add routing for clients
    routing_table.lock().unwrap().add_route(
        client1_identifier.clone(),
        client2_identifier.clone(),
        WildCard::No,
    );

    let destination_identifier = Identifier::new(client2_cert.get_pubk_hash().unwrap(), 0);

    let client1 = SyncClient::new(&config, client1_cert, allow_list).unwrap();

    client1
        .send_msg(0, destination_identifier.clone(), "hello".to_string())
        .unwrap();
    while let Some(msg) = client1
        .get_msg(destination_identifier.clone().id)
        .unwrap_or(None)
    {
        println!("{:?}", msg);
        client1
            .ack(destination_identifier.clone().id, msg.uid)
            .unwrap();
    }
}

pub fn init_tracing() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .parse("info,tarpc=off") // Include everything at "info"
        .expect("Invalid filter");

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
        .try_init()?;
    Ok(())
}
