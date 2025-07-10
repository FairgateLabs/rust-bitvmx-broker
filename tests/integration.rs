use bitvmx_broker::rpc::tls_helper::Cert;

use std::{
    fs::{self},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[cfg(not(feature = "storagebackend"))]
use bitvmx_broker::broker_memstorage::MemStorage;
#[cfg(feature = "storagebackend")]
use bitvmx_broker::broker_storage::BrokerStorage;
use bitvmx_broker::{
    allow_list::AllowList,
    channel::channel::{DualChannel, LocalChannel},
    rpc::{client::Client, errors::BrokerError, sync_server::BrokerSync, BrokerConfig},
};
#[cfg(feature = "storagebackend")]
use storage_backend::storage::Storage;
use tarpc::client::RpcError;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

#[cfg(not(feature = "storagebackend"))]
fn prepare_server(
    port: u16,
    privk_der: &str,
    allow_list: Arc<Mutex<AllowList>>,
) -> (BrokerSync, String, LocalChannel<MemStorage>) {
    let storage = Arc::new(Mutex::new(MemStorage::new()));
    let server_cert = Cert::new_with_privk(privk_der).unwrap();
    let server_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_cert,
        allow_list.clone(),
    )
    .unwrap();
    let server = BrokerSync::new(&server_config, storage.clone());
    let local = LocalChannel::new("1".to_string(), storage.clone());
    let pubk_hash = server_config.get_cert().get_pubk_hash().unwrap();

    (server, pubk_hash, local)
}

#[cfg(feature = "storagebackend")]
fn prepare_server(
    port: u16,
    privk_der: &str,
    allow_list: Arc<Mutex<AllowList>>,
) -> (BrokerSync, String, LocalChannel<BrokerStorage>) {
    let backend = Storage::new_with_path(&PathBuf::from(format!("storage_{}.db", port))).unwrap();
    let storage = Arc::new(Mutex::new(
        bitvmx_broker::broker_storage::BrokerStorage::new(Arc::new(Mutex::new(backend))),
    ));

    let server_cert = Cert::new_with_privk(privk_der).unwrap();
    let server_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_cert,
        allow_list.clone(),
    )
    .unwrap();
    let server = BrokerSync::new(&server_config, storage.clone());
    let local = LocalChannel::new("1".to_string(), storage.clone());
    let pubk_hash = server_config.get_cert().get_pubk_hash().unwrap();

    (server, pubk_hash, local)
}

fn prepare_client(
    port: u16,
    privk_der: &str,
    allow_list: Arc<Mutex<AllowList>>,
) -> (DualChannel, String, BrokerConfig) {
    let client_cert = Cert::new_with_privk(privk_der).unwrap();
    let client_config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        client_cert,
        allow_list.clone(),
    )
    .unwrap();
    let user = DualChannel::new(&client_config).unwrap();
    let pubk_hash = client_config.get_cert().get_pubk_hash().unwrap();
    (user, pubk_hash, client_config)
}

fn cleanup_storage(port: u16) {
    let _ = fs::remove_dir_all(&PathBuf::from(format!("storage_{}.db", port)));
}

fn create_allow_list(allow_list: Arc<Mutex<AllowList>>, pubk_hashes: Vec<String>) {
    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut allow_list = allow_list.lock().unwrap();
    for pubk_hash in pubk_hashes {
        allow_list.add(pubk_hash, addr);
    }
}

fn get_keys() -> (String, String, String) {
    let privk1 = "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100a757eeb2bc74fed438885e29060ae22d8c3ae9542fcac76e798fb4ce500a345ad260cf85072046a15b8e7c84c60514a1abb9c3d66e3c5121aaf3a1e4c2ba1e70da3ad26f2e8eb34ed6c6110c1ad6942a7f3e911f5b5fa7491698d3a97808aae28ba272116a42b25ffabe79510ab508a878d38e5246cd5a25172a5071fc4113039c266c1d6df17486548e78bc235c8f8a6316ffef15a04f0909ad55538f902a6b7b182f33307998e917d9a19808c203c53247c5600bd2ebb323e8758413df610d33290d7a6358886a3a115aeecbe2d899bb39a787bbc007cd08a786ac8efa1ff1bc5b8cfe699f89699abacff34eba15df504ad7099e4001b4e754e3c2904358c102030100010282010031cfe6e9a5575e1365d091d6bc49b911bdd03b6c27ddc0878dffccde2ccd1cd07c16fd2ea7f45f91e0630585b03c0aec24e5e2f98d4ebf07ba8f52fd7949558e5a2770445023821451b21b98f2d434be81a9ea20df5e15b997d45e0cf002047bf2fca3dfb335af4b0aa470104393a7c41e533ae61ad53da414c52fb4fe559086e24a0ed9fdfc38d2932c0079bf45e53999020a6227e2fb482208a69ba972f8b5866cb3e96923d10c20575f6de854b8705e59c66d4f21cd92171de980c7731bba12edf8f2e3e66c7d86d92bf408e95a3b93975f1f56a7245f83c3b338c0ccb864e59aea8cebef73f2dc8191cf7b798dc6bed4fcd3e8316b70e619efaf3b3b3bd102818100ebdafe144dc671cbf4c99c4e0c5caec184d905b10066165e18b39709da16f764208926667699cdcff5671beac9cd3ce1cf20d2ef84c01cc3d0cdb7853059c8387ab6d21dbc91dc9b569e24062fe6ade43a6639003ff0b01ff876acacc7f7cde243106a37058a1a11e431589a91786acdcfd27705093c103366fb6df0c8dd674702818100b5a2eaf6d9036537abbe182465375ad5625e0ec397493139c0b9ccedcbbf6783745aeeaf0e006a0ae42592ad82f34c0b595c5209c81f2fe33e1ba05af22b1ce22d075c78fc51d205c023f7e73bb2a344f01f093cec36b5ea5f0b04c60964260d30c0c44bf3899983e79c552937c1f0c5da99ebe53b3ce6b6f8413d0230a9d3b702818100ae778561c1929d1531537de32233e135d7aeae0e1bec68795cae6478ee31f4f8c5348f0a568b397aaede8201311c380015b7033218b1ffd53dfd1ed75047e9db15b36d447ffc2a03629482b36cf5a8065ec8c53b9110db481b04b680ed3f3ab637c3c9be3fc3c3bb1e60fe590068e220b2adce4b1464b0db453f9238fe6d00fb0281807399828d2444c2f0917f648215610b906f1089b8f5da01584e4e721c8de5fd8d6e4a494a6450e32c97534a6cdfc0d48f0c8a73340287c6c48bccad5bf47077eb82d9028385a2d5560f9954b77809135c56ae8a049a199fe1d027851c3cf1de3ddadf748f1a2a62e7ce4a72f0cea9c2014a45581b067e961fb114642db6a6ff3502818100e297059b5a7347256c4ba42c7e8c6b309c039fb31a3c880a10922e15b7ed4f809331182ea0a086b83c4de6205e64ea8ac6029f5c0193a9ff136463c9c611c1369c90b0e958aca41d3e1a432cd76a64055e300b6b82cf084065b9351b45c10955791447bf578f2e60544d5d50187f903deaeea1e86e6c8c8c04151b5f5eaade52";
    let privk2 = "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100b6ae502944279e82b34c4beb10f67dba10cd25fae819210acc8ed4e3d4a814e5aee3b00c688ebe843b47f766427e8c66dcb1136128b5a8ea44f16116cf8cc84cbb55f2f0c59b0ec1a1ce99b2bcd9f32743a1e24dcc43c6182c43d3584b0a357ed716d19d2a1b18d5028d11f301ae0615a5e1dceaa309985353d31f1421f9767b7fe811f2138af51d9034619585561d6384fc58998af1d75ce7b7b54f814973823b9f79e9889bd7cf3c6d7ef05b722bdf7b54f69d38123f4f7425b49681b996738374ee680a8ae445393ca20c1818fb89be340716ff9d6c15d0aff5e16d1f11f0bd8df540b8ed5c340c4e636ce642ee10aeb8e0059f7c16cfca024ed3970272e3020301000102820100451805faadabfc807bb742499cc756034f828038779bb58b23966c3fe5b952fa125d4cc34cb29cad5fcc96eea6fcbd36d486e7090b00366cb0f9c8da7b52c899790b8790f8746eaedef7c8db3921881d942f80ec22f38953b03e510be689ec74d67e6b76b1abc10723e95e5e16870f07161028e1d81b737124d5c7bdf221abe5637b043d7fbe753db1314056ef65c072ad36f256347eed583548dea9c6acaec60d4241c3b68c4eb5ff9395753765ffa5e1f6b059730934915d54f8c1526f91b8583acf42908bd55980bfde2d692515eb0ca311fe36e3a1e2dc0a52714a708531a48bfd52050c679cb62a784fbc35ccbf91cbdd624acc8ce6b95160dd3f17226102818100dca5d1aa43ad9871ad3775c4452e698d68191bad9734675c7bd4e8ee9c1ff1c05d1d3927fec729c3868784c59f816acbb355e5041af8465df0aa708253cea1fbfb4b11d0f4436f8c2eae5782bb0285911d65ac8588845e96f36344ea68359f504aff170960329d7a0e95a0c35541f53fbb4163456e8d8dc610ac149ea2131f0302818100d3f33b1dd06ee417cd69ef8f2d17ddcdd80155262bebf9e597fac7aed9d93577fbde150c93ad98cb0ceb5f854e1e224f376c0f4f1f168447af3ca328971b7fc4dc98c447a5cf8296ed72c3610e5d3ddd36647a25cc9d0f4451264ee81620075b02e4872f10a86563d5764e765b1a4bcd23bea231489ec43e8db219fa4ba0a6a102818001b1881d6d6d8ca8fab25d46075de6d37e040b5156c2c1345582f9d2b3020fc1f13503364a5f4ef3c039940c4c401b08bb34a2905880a5519d4241a0ce71dc8e698c56f3aa9c45e3e68bd2021fdb52191e07a4be55a0e674f42343e924a99cb26a10f1255246b12cb9a5ee58f17393254d13a0666d05cb1bc50efd0d86a2ecef028180244a100421cceac6dc87d7d986da00431f49d31f6f03bf4cbd41d5f0ad221092939049c05684b1958a87be5a1faeef26eb115869aea3f75022c3da17b80fa047bf917481e3f4eca214d3c27a1ab082481ee90334f79ca8a184d76f4933889659d1dbf8fd68f7bc2c64bf15de13e923b362fc5fdeda553cba8d1e426e6586832102818016df4e6d5dca014855917b6e9e7fcd82cf8e766c89ca1ade85205bd7ef465545367ec9139ff828a35076eadfd25a0f81cb31f44fa02bb2c6d21e2bf80fab52ca0a8f46b0864f0c2be5233a7d5c8911e0cb5ea51415be4da46235a08762d579b252b7a96470758257d320afa6d12eb8708108b49c4cf5140e94800a855c48ec44";
    let privk3 = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100a986f0b8f6f445a6bc68b034f58888ed31156d03902aabfb0c9a4fb6946968ccb79596f9fb6904c79883b3a2f23774ea476368bfdf7e5345e1c8f74d94013f33d39792fdcfb26afd0b5a54e0753da370c79eefbd7293904de805d81317eebee1bb9cbb1f3e2c47923cf538ea0b72e107bc36134ad77e83ea86881dcf97e73e2ca1cc56be4c1496e9d7f5cc9bb0febc500ea0180f185306141267188c57b56fdcdca152c02557ad7fd31e517e7454ce2697432ad3982eb0b3dcaff2da83a8fda8357df39cb4dd24ddfcdc8f975a5ec9847f1fb29e81dd7ab787e2064051e9eb73fd683c3d79e2e30818fb5551d471b633fbff1c58078275a9414938c3e44dc0510203010001028201000269d6617bba8c874c255d64d39e06fd0176e19f6c5cff27cacd239760d383576ec1a56d97a3ae1abd541aa996332de9ebec416081e9057c78336939e4828408d3d95391637491cb5a6f05c85042f961b0a5d599e7d8abf43ffa5d52204418d993d72e5eca7ecce20b161ea24e596b54b5dc3b38148b4b8b7a30d3e3d1b0cc14c6a08a69293bcd3b006a6cd89f1c00d7baeecbd8126143b3995200e1965b72af78c63f4a997697f0067c4658aff4788c7bda7015527f4c4793ab8cbf1cf5aca4edb85849f6038a0f3d75d59c44e2635c5a29bf10e18af67b3e20d1f015000b752a044d2cb9a258c9e7f655a683dd82114d01b975206eaf9a8bb7c2662bd9c07502818100e378eb07040d5212541e88ea3f9c64d8274512444aec3b27ef4acf04a8b0b5f06b80b383d6977fc98e39ef861a56ffc9b086bf618598d5a57aaf135e2b282397e29147932159112f39d7ca9b5061c78db39f754699793f149c835b7357480f33407740e86c8a6d0fdded695f6d4b9fa0e6140e8d2a978fcd77ab22d9d341fd5702818100bec9ab746de75025433e5c5ff6902d4951f244efc85ed02c564146134790ecb4e3e59c88a752dd25d3c380b6247175335beb5b52a23137d50ce8e3252c1c893ac0e098bf229b611e9155b179922d3b61a92d09dc8ade99f7cfa3cb34704edef07ce1d68eb9a386a33d75323af91d538a48f255b8c8aa2228cd19ccf28103fe970281804aed22655e35510a4e80fc52447fac4bf2ab72b7e201ebfe5c78c4b5e126cbd71462013f74e8d423bce06280469ecf844ccc25afe6c48fe301053818f59834192c7cf419878b81f88f52001fa69b7e92b34edbdf546036a20067d830a6d84a81744393b2bb45e164af922afa4ed2f1129b9691b0780e1244f89cfb4ecaa25ae30281810093c5ce5822dc1c16908bd7aeb86219c1858839dee37a949112ca0205e2d39c93cb44c8468c1b41911001884b0bd5192b0b92332cc0d59062235aaabcdafacb4bc7a2ee8c74b896b3bf6bf947a972016176509d27c623fe6b93d751082fc8d722bc078c5105f663cd4247e8fd0680b1791561260636de9810b433bcab44449cc702818033a2ff023fea2a94259d149a12467349cf38d1477fcbedecb255aff76c791aaba2bec026771b0217b38b522591cf1b0a557d8f2e0927bdbc4c7d232bc530d86eccb82d0f48cf0fea3c6ca9c0c77fa70cdec41100059b3b0fedc213a212b4c768647371b0ea89bf38cbd79340c44e427e8dd395a0470cf6d11dea985223d34de3";
    (privk1.to_string(), privk2.to_string(), privk3.to_string())
}

#[test]
fn test_channel() {
    init_tracing().unwrap();
    let port = 10000;
    cleanup_storage(port);
    let (privk_server, privk_user_1, privk_user_2) = get_keys();
    let allow_list = AllowList::new();
    let (mut server, pubk_hash_server, _) = prepare_server(port, &privk_server, allow_list.clone());
    let (user_1, pubk_hash_1, _) = prepare_client(port, &privk_user_1, allow_list.clone());
    let (user_2, pubk_hash_2, _) = prepare_client(port, &privk_user_2, allow_list.clone());
    create_allow_list(
        allow_list.clone(),
        vec![pubk_hash_server, pubk_hash_1.clone(), pubk_hash_2.clone()],
    );
    user_1.send(pubk_hash_2, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, pubk_hash_1);
    server.close();
    cleanup_storage(port);
}

#[test]
fn test_ack() {
    let port = 10001;
    cleanup_storage(port);
    let (privk_server, privk_user_1, privk_user_2) = get_keys();
    let allow_list = AllowList::new();
    let (mut server, pubk_hash_server, _) = prepare_server(port, &privk_server, allow_list.clone());
    let (_, pubk_hash_1, client_config) = prepare_client(port, &privk_user_1, allow_list.clone());
    let (_, pubk_hash_2, _) = prepare_client(port, &privk_user_2, allow_list.clone());
    create_allow_list(
        allow_list.clone(),
        vec![pubk_hash_server, pubk_hash_1.clone(), pubk_hash_2.clone()],
    );

    let client = Client::new(&client_config).unwrap();
    client
        .send_msg(pubk_hash_1, pubk_hash_2.clone(), "Hello!".to_string())
        .unwrap();

    let msg = client.get_msg(pubk_hash_2.clone()).unwrap().unwrap();
    assert_eq!(msg.msg, "Hello!");
    let msg_dup = client.get_msg(pubk_hash_2.clone()).unwrap().unwrap();
    assert_eq!(msg.uid, msg_dup.uid);
    assert!(client.ack(pubk_hash_2.clone(), msg.uid).unwrap());
    println!("{:?}", client.get_msg(pubk_hash_2.clone()).unwrap());
    assert!(client.get_msg(pubk_hash_2.clone()).unwrap().is_none());
    server.close();
    cleanup_storage(port);
}

#[test]
fn test_reconnect() {
    let port = 10002;
    cleanup_storage(port);
    let (privk_server, privk_user_1, privk_user_2) = get_keys();
    let allow_list = AllowList::new();
    let (mut server, pubk_hash_server, _) = prepare_server(port, &privk_server, allow_list.clone());
    let (_, pubk_hash_1, client_config) = prepare_client(port, &privk_user_1, allow_list.clone());
    let (_, pubk_hash_2, _) = prepare_client(port, &privk_user_2, allow_list.clone());
    create_allow_list(
        allow_list.clone(),
        vec![pubk_hash_server, pubk_hash_1.clone(), pubk_hash_2.clone()],
    );

    let client = Client::new(&client_config).unwrap();

    client
        .send_msg(
            pubk_hash_1.clone(),
            pubk_hash_2.clone(),
            "Hello!".to_string(),
        )
        .unwrap();
    let msg = client.get_msg(pubk_hash_2.clone()).unwrap().unwrap();
    assert_eq!(msg.msg, "Hello!");
    assert!(client.ack(pubk_hash_2.clone(), msg.uid).unwrap());
    server.close();

    std::thread::sleep(std::time::Duration::from_secs(2));

    let (mut server, _, _) = prepare_server(port, &privk_server, allow_list.clone());
    std::thread::sleep(std::time::Duration::from_secs(1));

    client
        .send_msg(pubk_hash_1, pubk_hash_2.clone(), "World!".to_string())
        .unwrap();
    let msg = client.get_msg(pubk_hash_2).unwrap().unwrap();
    assert_eq!(msg.msg, "World!");
    server.close();
}

#[test]
fn test_stress_channel() {
    let port = 10003;
    cleanup_storage(port);
    let (privk_server, privk_user_1, privk_user_2) = get_keys();
    let allow_list = AllowList::new();
    let (mut server, pubk_hash_server, _) = prepare_server(port, &privk_server, allow_list.clone());
    let (user_1, pubk_hash_1, _) = prepare_client(port, &privk_user_1, allow_list.clone());
    let (user_2, pubk_hash_2, _) = prepare_client(port, &privk_user_2, allow_list.clone());
    create_allow_list(
        allow_list.clone(),
        vec![pubk_hash_server, pubk_hash_1.clone(), pubk_hash_2.clone()],
    );

    for i in 0..1000 {
        println!("Sending: {}", i);
        let send_ok = user_1.send(pubk_hash_2.clone(), "Hello!".to_string());
        if send_ok.is_err() {
            println!("Error: {:?}", send_ok);
        }
        assert!(send_ok.is_ok());

        let mut ok = false;

        while !ok {
            let try_recv = user_2.recv();
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
            assert_eq!(msg.1, pubk_hash_1.clone());
        }
    }
    server.close();
    cleanup_storage(port);
}

#[test]
fn test_local_channel() {
    let port = 10010;
    cleanup_storage(port);
    let (privk_server, privk_user_1, privk_user_2) = get_keys();
    let allow_list = AllowList::new();
    let (mut server, pubk_hash_server, _) = prepare_server(port, &privk_server, allow_list.clone());
    let (user_1, pubk_hash_1, _) = prepare_client(port, &privk_user_1, allow_list.clone());
    let (user_2, pubk_hash_2, _) = prepare_client(port, &privk_user_2, allow_list.clone());
    create_allow_list(
        allow_list.clone(),
        vec![pubk_hash_server, pubk_hash_1.clone(), pubk_hash_2.clone()],
    );

    user_1.send(pubk_hash_2, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();
    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, pubk_hash_1);
    server.close();
    cleanup_storage(port);
}

#[test]
fn test_dinamic_allow_list() {
    let port = 10004;
    cleanup_storage(port);
    let (privk_server, privk_user_1, privk_user_2) = get_keys();
    let allow_list = AllowList::new();
    let (mut server, pubk_hash_server, _) = prepare_server(port, &privk_server, allow_list.clone());
    let (user_1, pubk_hash_1, _) = prepare_client(port, &privk_user_1, allow_list.clone());
    let (user_2, pubk_hash_2, _) = prepare_client(port, &privk_user_2, allow_list.clone());
    create_allow_list(
        allow_list.clone(),
        vec![pubk_hash_server, pubk_hash_1.clone(), pubk_hash_2.clone()],
    );

    allow_list.lock().unwrap().remove(&pubk_hash_2.clone());

    user_1
        .send(pubk_hash_2.clone(), "Hello!".to_string())
        .unwrap();
    let msg = user_2.recv().unwrap_err();
    assert!(matches!(msg, BrokerError::RpcError(RpcError::Channel(_))));

    allow_list
        .lock()
        .unwrap()
        .add(pubk_hash_2.clone(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    user_1.send(pubk_hash_2, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();

    assert_eq!(msg.0, "Hello!");
    assert_eq!(msg.1, pubk_hash_1);

    server.close();
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
