# rust-bitvmx-broker

`rust-bitvmx-broker` is a message broker library implemented in Rust. It moves messages between endpoints over mutually authenticated TLS, persists them so a restart does not lose anything in flight, and enforces who is allowed to send to whom.

Endpoints may sit in separate processes on different machines, or share a single process with the broker. Both are supported, with the same operations either way.

Identities are certificate public key hashes. An allow list controls which identities may connect, and a routing table restricts which of them may send to which.

## Documentation

The `docs/` folder explains what a new developer needs without reading the source:

- [`docs/architecture.md`](docs/architecture.md): components, the two topologies, the message lifecycle, the tick model, and the delivery contract.
- [`docs/security.md`](docs/security.md): identities, the allow list, the routing table, and the limits a broker enforces on its callers.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

## Key Features

- 🔐 **Mutually authenticated TLS**: both ends present a certificate and each checks the other against an allow list.
- 🧾 **Identity by public key hash**: a peer is named by the hash of its certificate public key.
- ✅ **Allow list**: which identities may connect, pinned to an IP.
- 🗺️ **Routing table**: which identity may send to which, with wildcards.
- 💾 **Persistent queues**: outgoing, incoming, and dead letter queues survive a restart, backed by `rust-bitvmx-storage-backend`.
- 🔁 **Automatic retries**: undelivered messages are retried with a growing delay and land in the dead letter queue once their attempts run out.
- ⏱️ **Rate limiting** per sender, plus caps on message size and queue depth.
- 🧭 **Error severity**: every error reports whether it is fatal, so a refused message does not have to stop a process.

## Components

| Type | What it is | Operations |
|---|---|---|
| `BrokerNode` | A client and a server in one. Listens for other brokers and sends to them, with persistent queues in between. | `tick` deliver the outgoing queue and collect what arrived<br>`send_peer` queue a message for a broker on another machine<br>`send_service` hand a message to a component on this broker<br>`check_receive` take what arrived, oldest first<br>`check_deadletter` take what ran out of attempts, with its context<br>`create_local_channel` give a component its own channel<br>`get_pubk_hash` / `get_address` / `get_local_id` how others address this node<br>`close` stop the listener and drain connections in flight |
| `BrokerServer` | The receiving half on its own. A TLS listener plus the storage that holds messages for the destinations it serves. | `create_local_channel` and `close`, as above |
| `RemoteChannel` | Reaches a broker over the network. For a component in another process, or on another machine. | `send` send to a destination identifier<br>`send_server` address the broker itself<br>`get` read the oldest message waiting<br>`ack` acknowledge by uid |
| `LocalChannel` | Reaches a broker in the same process. No network and no serialization. Only a broker can hand one out. | `send`, `get` and `ack`, as above<br>`get_all` read everything waiting, oldest first |
| `BrokerClient` | The request layer under `RemoteChannel`. | `send_msg`, `get_msg` and `ack`, the same three one level down |
| `AllowList` | Who may connect. One fingerprint per entry, optionally pinned to an address. Checked on every connection. | `from_file` / `from_certs` load from YAML, or build from certificates<br>`add_entry` / `remove` admit or drop an identity<br>`is_allowed` the check run on every connection<br>`generate_yaml` write it back to disk |
| `RoutingTable` | Who may send to whom. Rules from sender to destination, or a mode that accepts one destination or all. Checked on every message. | `from_file` load from YAML<br>`add_route` / `add_routes` / `remove_route` permit or withdraw one sender reaching one destination<br>`allow_only_to` accept a single destination whoever sent it<br>`can_route` the check run on every message<br>`save_to_file` write it back to disk |

The allow list and the routing table are held behind a lock and reachable at runtime through `get_allow_list` and `get_routing_table`, so an identity can be admitted or withdrawn without restarting the broker.

A `BrokerNode` is built in one of two modes, and the mode decides which send method is available:
- **Peers** (`new_peers`): talks to brokers on other machines. It accepts only messages addressed to itself, and `send_peer` queues a message for another broker, which `tick` delivers.
- **Services** (`new_services`): serves several components inside one process. It takes a routing table naming who may talk to whom, and `send_service` hands a message to another component on the same broker.

Both are built either from values or from file paths, with `new_peers_with_paths` and `new_services_with_paths` reading the key, the allow list, and the routing table from disk.

See [`docs/architecture.md`](docs/architecture.md) for how the two fit together.


## Behaviour to know

- **Receiving happens on its own.** The listener accepts connections and stores what arrives whether or not anything is ticking. Messages wait in storage until a `tick` moves them into the incoming queue, and `check_receive` then hands them to the caller.
- **`send_peer` is the only send that waits for a `tick`.**. `send_service` and the channel sends reach storage immediately.
- **Receivers must be idempotent.** Delivery is at-least-once, so the same message can arrive twice.
- **Take messages, then acknowledge.** `get` and `ack` are separate so that a caller which stops midway resumes from the last acknowledged message instead of losing what it was holding.
- **Check `is_fatal` before stopping.** Some errors mean one message or one peer was refused, not that the process cannot continue.

## Usage

`examples/` holds runnable programs for a server and a client, and `tests/integration.rs` exercises every path end to end. `examples/` also carries a sample allow list and routing table, and `config/broker_settings.yaml` a sample settings file.

## Configuration

Settings live in `BrokerSettings`, loaded from YAML. A sample is in `config/broker_settings.yaml`. Every group is optional and falls back to the defaults in `src/settings.rs`.

| Group | What it controls |
|---|---|
| `rate_limiter_config` | How many requests one sender may make, and how fast that budget refills. |
| `broker_node_config` | How many messages a tick delivers and collects, and the retry attempts and delays before the dead letter queue. |
| `msg_size_config` | The largest message the broker accepts. |
| `queue_config` | How many messages one sender may have waiting for one destination. |

The allow list and routing table are separate YAML files. Their formats, and what each setting protects, are in [`docs/security.md`](docs/security.md).

## Development Setup

```bash
# Build everything, including examples and tests.
cargo check --all-targets

# Unit tests.
cargo test --lib

# Integration tests.
cargo test --test integration
```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🧩 Part of the BitVMX Ecosystem

This repository is a component of the **BitVMX Ecosystem**, an open platform for disputable computation secured by Bitcoin.  
You can find the index of all BitVMX open-source components at [**FairgateLabs/BitVMX**](https://github.com/FairgateLabs/BitVMX).

---
