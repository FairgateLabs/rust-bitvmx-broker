# Rust BitVMX Broker

# Overview

Rust BitVMX Broker is a message broker implemented in Rust. It provides a way to send and receive messages between clients using a synchronous server (`sync_server`), a client (`Client`), and a dual-channel (`DualChannel`) or a persistent queue-based channel (`QueueChannel`) for communication

The broker uses TLS certificates for authentication, verifying only the public key hash of each certificate. An allowlist controls which identities are trusted, and a routing table restricts which clients are allowed to communicate with each other.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

## Features

- 🖥️ **Synchronous server** for handling message requests  
- 📡 **Asynchronous and synchronous client** for sending and receiving messages  
- 🔄 **Dual-channel** for bidirectional communication  
- 🔐 **TLS authentication** with self-signed certificates  
- 🧾 **Verification** by certificate public key hash  
- ✅ **AllowList management** with optional wildcard  
- 🗺️ **Routing table** to restrict client-to-client communication
- ⏱️ **Rate-limited message delivery**
- ☠️ **Dead letter queue** for undeliverable messages

## Methods

### Identification
- **from_file / load_from_file**: Create an allow list or routing table from a `.yaml` file  
- **from_certs**: Create an allow list from certificates  
- **add**: Add a specific public key hash and address to the allow list  
- **add_routes**: Add routes to the routing table  
- **remove**: Remove a specific public key hash from the allow list  
- **remove_route**: Remove a route from the routing table  
- **remove_all / remove_all_to**: Remove all routes from the routing table, or only those to a specific destination  
- **generate_yaml / save_to_file**: Export the allow list or routing table to a `.yaml` file  

### Communication

#### Client
The `Client` API provides direct message-based communication with explicit
acknowledgement handling.
- **send_msg**: Send a message to a destination identifier  
- **get_msg**: Receive a message for a given identifier  
- **ack**: Acknowledge receipt of a message  

#### DualChannel
`DualChannel` is a higher-level abstraction built on top of `Client` that provides bidirectional communication.
- **send**: Send a message to a specific destination identifier  
- **send_server**: Send a message directly to the server  
- **recv**: Receive the next available message  

#### QueueChannel

`QueueChannel` is a persistent messaging abstraction designed for reliable delivery and fairness across destinations.
Messages are stored in queues and processed incrementally using a tick-based model. Delivery attempts are retried automatically.

Queues managed internally:
- **OutQueue**: Messages pending delivery
- **InQueue**: Successfully received messages
- **DeadLetterQueue**: Messages that could not be delivered

Main methods:
- **send**: Enqueue a message for delivery
- **tick**: Process outgoing and incoming queues
- **check_receive**: Retrieve received messages
- **check_deadletter**: Retrieve messages that failed delivery

## Usage

### Creating a Sync Server

To create a synchronous server, you need to initialize the server with a configuration, storage, certificate, allow list and routing table.

```rust
fn main() {
    let storage = Arc::new(Mutex::new(MemStorage::new()));

    let server_cert = Cert::new().unwrap();
    let server_pubkey_hash = server_cert.get_pubk_hash().unwrap();

    let allow_list = AllowList::new();
    let routing_table = RoutingTable::new();
    
    let config = BrokerConfig::new(10000, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), server_pubkey_hash).unwrap();
    let server = BrokerSync::new(&config, storage.clone(), server_cert, allow_list, routing_table);
    // Start the server...
}
```

### Creating a Client

To create a client, you need to initialize it with a configuration, certificate and allow list.

```rust
fn main() {
    let client1_cert = Cert::new().unwrap();
    let client2_cert = Cert::new().unwrap();

    let destination_identifier =
        Identifier::new(client2_cert.get_pubk_hash().unwrap(), 0);

    let client1 = Client::new(&config, client1_cert, allow_list).unwrap();

    client1.send_msg(0, destination_identifier.clone(), "hello".to_string()).unwrap();
    while let Some(msg) = client1.get_msg(destination_identifier.clone()).unwrap_or(None)
    {
        println!("{:?}", msg);
        client1.ack(destination_identifier.clone(), msg.uid).unwrap();
    }
}
```

### Creating a DualChannel

To create a dual-channel, you need to initialize it with a configuration, certificate, address and allow list.

```rust
fn main() {
    let local_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let (server_cert, client1_cert, client2_cert) = (
        Cert::new().unwrap(),
        Cert::new().unwrap(),
        Cert::new().unwrap(),
    );
    let certs = vec![server_cert.clone(), client1_cert.clone(), client2_cert.clone()];
    let addrs = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); certs.len()];
    let allow_list = AllowList::from_certs(certs, addrs).unwrap();
    let server_pubkey_hash = server_cert.get_pubk_hash().unwrap();
    let client2_identifier = Identifier::new(client2_cert.get_pubk_hash().unwrap(), 0);

    let client1_addr = SocketAddr::new(local_addr, 10001);
    let client2_addr = SocketAddr::new(local_addr, 10002);

    let server_config = BrokerConfig::new(10000, Some(local_addr), server_pubkey_hash).unwrap();
    
    let user_1 = DualChannel::new(&server_config, client1_cert, 0, allow_list);
    let user_2 = DualChannel::new(&server_config, client2_cert, 0, allow_list);

    user_1.send(client2_identifier, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();
    server.close();
}
```

### Creating a QueueChannel 
```rust
fn main() {
    let queue_channel1 = QueueChannel::new(
        "testqueue",
        sender.address,
        &sender.privk,
        sender.storage,
        None,
        allow_list,
        routing_table,
    ).unwrap();

    let queue_channel2 = QueueChannel::new(
        "testqueue",
        receiver.address,
        &receiver.privk,
        receiver.storage,
        None,
        allow_list,
        routing_table,
    ).unwrap();

    queue_channel1.send(
        "example_ctx",
        &queue_channel2.get_pubk_hash().unwrap(),
        queue_channel2.get_address(),
        b"Hello, Queue!".to_vec(),
    ).unwrap();

    queue_channel1.tick().unwrap();
    queue_channel2.tick().unwrap();

    let received = queue_channel2.check_receive().unwrap();

    queue_channel1.close();
    queue_channel2.close();
}
```

## Development Setup

1. Clone the repository
2. Install dependencies: `cargo build`
3. Run tests: `cargo test -- --ignored`

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🧩 Part of the BitVMX Ecosystem

This repository is a component of the **BitVMX Ecosystem**, an open platform for disputable computation secured by Bitcoin.  
You can find the index of all BitVMX open-source components at [**FairgateLabs/BitVMX**](https://github.com/FairgateLabs/BitVMX).

---
