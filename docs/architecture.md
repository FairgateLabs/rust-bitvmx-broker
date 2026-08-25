# Architecture

What the [README](../README.md) leaves out: where messages physically live, the path one takes from a `send` to a `check_receive`, and what the library guarantees along the way. Identifiers, storage, the delivery guarantees and the severity model hold for every type. Queues, ticks and retries exist only on `BrokerNode`. Each section below says which it is.

## What an identifier names

*Applies to every type.*

An endpoint is a certificate public key hash plus a `u8`, written `hash:id`, for example `a1b2c3:0`. The hash says which process. The id separates endpoints that share one certificate, so a process holding a single key can still expose several inboxes. Both halves are matched exactly when a message is stored or routed, so `a1b2c3:0` and `a1b2c3:1` are different destinations with different queues.

## Where messages live

Two stores exist. Which of them a caller touches depends on the type it holds.

- **Server storage**, owned by `BrokerServer`, and every broker has one. The server opens the path itself and nothing else may use it. It holds one queue per destination the server serves, filled by whoever connects and drained when the owner acknowledges. Any message arriving from outside the process lands here. For a plain `BrokerServer` it is the only storage.

- **Node storage**, owned by the caller, and only a `BrokerNode` has one. The node is handed an already open store and shares it with the rest of the process, namespaced by the name the node was built with, so several nodes can use one store without colliding. It holds the node's three queues.

A `LocalChannel` reads and writes server storage directly, which is why one can only be created from a server rather than built on its own. That is what guarantees the channel and the server are looking at the same messages instead of at two handles onto the same path.

Node storage is strongly recommended to be transactional. A node removes a message from its incoming queue as it hands it over, so only a rollback puts it back if handling then fails. Without one, a message taken and not handled is gone. Server storage is the broker's own and never part of that transaction, so anything accepted from the network is durable the moment it is stored.

## The queues a node keeps

*`BrokerNode` only.*

| Queue | Holds | Written by |
|---|---|---|
| Outgoing | Messages waiting to reach another broker, each with its retry state. | `send_peer` |
| Incoming | Messages that arrived and are waiting to be taken. | `tick`, from server storage |
| Dead letter | Messages that ran out of delivery attempts, with the context they were sent under. | `tick`, when attempts are exhausted |

All three are persistent, so a restart resumes where it left off.

## Sending a message

Three paths, and which one a message takes decides whether it is durable before the call returns.

**Queued, `BrokerNode::send_peer`.** The message is written to the outgoing queue with a fresh retry state and the call returns.The next `tick` walks the queue oldest first and delivers every message whose retry delay has elapsed. A delivered message is removed from the outgoing queue. A failed one has its attempt recorded and its next retry pushed further out. Once the attempts run out it moves to the dead letter queue. Each tick delivers at most a fixed number per destination, so one unreachable or slow destination cannot consume the whole pass.

**Immediate over the network, `RemoteChannel::send` and `BrokerClient::send_msg`.** The call connects if needed, sends, and returns once the receiving broker has stored the message. There is no queue and no retry, so a failure is the caller's to handle.

**Immediate in-process, `LocalChannel::send` and `BrokerNode::send_service`.** The message goes straight into server storage, with no network and no serialization. Note that this path does not pass the connection checks: the rate limit, the queue cap and the routing table are applied to what arrives over a connection, and a local send has no connection. Components sharing a process are inside the boundary those checks defend.

## Receiving a message

Steps 1 and 2 are the server and happen for any broker. Steps 3 and 4 are `BrokerNode` only.

1. The sender's broker connects and authenticates. This runs on the listener's own runtime, with no tick involved.
2. The receiving server checks the request against its limits and its routing table, then writes the message into server storage under the destination it names.
3. The receiving node's next `tick` moves everything addressed to its own identifier into the incoming queue and acknowledges it on the server side.
4. `check_receive` hands those messages to the caller.

## Inside a tick

*`BrokerNode` only.* One pass, in order:

1. **Outgoing.** Deliver what is due, retry what failed, retire what is exhausted to the dead letter queue.
2. **Incoming.** Move what the server received into the incoming queue and acknowledge it on the server side.

## Delivery guarantees

*Apply to every path, queued or immediate.*

**At-least-once, never at-most-once.** A message that is accepted will arrive, possibly twice. Reading and acknowledging are separate steps so that a caller which stops midway resumes from the last acknowledgement rather than losing what it was holding. The cost is that the same message can be handed out again, which is why receivers have to be idempotent.

**Oldest first, within one queue.** Messages come back in the order their queue received them. Nothing is promised about the relative order of two messages that were sent by different senders.

**Delivery is not a receipt.** A successful send means the destination's broker stored the message. It says nothing about whether the component behind it has acted on it, or is even running. 

**Nothing is dropped silently.** A message that runs out of delivery attempts ends up in the dead letter queue with the context it was sent under, so the sender can tell which piece of work was lost. Entries stay until they are taken. This one needs a `BrokerNode`, since it is the only type that retries.

## Error severity

*Applies to every type.* Every error answers `severity()`:

| Severity | Means | `is_fatal()` |
|---|---|---|
| `Fatal` | The process cannot continue. A poisoned lock, or a failure while constructing the broker. | `true` |
| `NonFatal` | One message, one row, or one peer was refused or failed. Keep serving. | `false` |
| `Programming` | The API was misused. | `true` |

The distinction matters because a refused message and an unusable process arrive through the same `Result`. 

## Settings reference

`BrokerSettings` is loaded from YAML. Every group is optional and falls back to the defaults in `src/settings.rs`. The [README](../README.md#configuration) lists the groups. The fields are:

| Group | Field | Controls | Applies to |
|---|---|---|---|
| `rate_limiter_config` | `rate_limit_capacity` | Requests one sender may make before it has to wait. | Any receiving broker |
| | `rate_limit_refill_rate` | How fast that budget returns, per second. | Any receiving broker |
| | `tokens_per_message` | Requests charged per message sent. | Any receiving broker |
| `broker_node_config` | `max_msgs_per_tick_utilization` | Share of the rate budget one tick may spend per destination. | `BrokerNode` |
| | `max_send_attempts` | Delivery attempts before a message is retired to the dead letter queue. | `BrokerNode` |
| | `retry_min_delay_msecs` | Delay before the first retry. | `BrokerNode` |
| | `retry_max_delay_msecs` | Ceiling on the delay, which grows with each attempt. | `BrokerNode` |
| `msg_size_config` | `max_frame_size_kb` | Largest message accepted, measured as it travels. | Any broker, and the sender |
| `queue_config` | `max_queue_depth` | Messages one sender may have waiting for one destination. | Any receiving broker |

`max_queue_depth` should stay at or above the number of messages one tick can deliver, or a tick can never spend its budget. And `max_frame_size_kb` covers the message as encoded for transport, which is slightly larger than the payload in memory, so the usable payload limit sits a little below the configured number.
