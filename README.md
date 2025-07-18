# Rust BitVMX Broker

Rust BitVMX Broker is a message broker implemented in Rust. It provides a way to send and receive messages between clients using a synchronous server (`sync_server`), a client (`Client`), and a dual-channel (`DualChannel`) for communication.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

## Features

- Synchronous server for handling message requests.
- Asynchronous client for sending and receiving messages.
- Dual-channel for bidirectional communication.

## Quick Start

### Creating a Sync Server

To create a synchronous server, you need to initialize the server with a configuration and storage.

```rust
fn main() {
    let storage = Arc::new(Mutex::new(MemStorage::new()));
    let config = BrokerConfig::new(10000, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server = BrokerSync::new(&config, storage.clone());
    // Start the server...
}
```



### Creating a Client

To create a client, you need to initialize it with a configuration.

```rust
use bitvmx_broker::rpc::client::Client;
use bitvmx_broker::rpc::BrokerConfig;

fn main() {
    let config = BrokerConfig::new(10000, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let client = Client::new(&config);

    let ret = client.send_msg(1, 2, "hello".to_string());

    while let Some(msg) = client.get_msg(2).unwrap_or(None) {
        println!("{:?}", msg);
        client.ack(2, msg.uid).unwrap();
    }
}
```

### Creating a DualChannel

To create a dual-channel, you need to initialize it with a configuration and an ID.

```rust
use bitvmx_broker::channel::channel::DualChannel;
use bitvmx_broker::rpc::BrokerConfig;

fn main() {
    let config = BrokerConfig::new(10000, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    
    let user_1 = DualChannel::new(&config, 1);
    let user_2 = DualChannel::new(&config, 2);

    user_1.send(2, "Hello!".to_string()).unwrap();
    let msg = user_2.recv().unwrap().unwrap();
    server.close();
}
```
## License

This project is licensed under the MIT License.