# Access control

The [README](../README.md) says a broker authenticates by public key hash and restricts who may send to whom. This is what those checks actually establish, how the two files are written, and what the broker refuses once a caller is past them.

## What a fingerprint proves, and what it does not

An identifier has two halves, and they are not equally trustworthy.

The **hash** comes from the certificate presented during the handshake. A caller cannot choose it, claim someone else's, or change it once connected. It is stamped on every message the broker stores, and it is also what `get` and `ack` answer for, so a participant can neither send as another nor read another's messages.

The **id** is addressing rather than authentication, and it exists for the services topology, where one broker serves several components in a process and each needs an inbox of its own. Those components can share a certificate and be told apart by id, or hold separate keys, or both. Components sharing a key can therefore address each other's inboxes, which is unremarkable between parts of one process that already trust each other.

## The handshake check

Both ends run the same four steps, in both directions:

1. The TLS handshake completes and each side takes the other's certificate.
2. It hashes the public key to get a fingerprint.
3. It looks that fingerprint up in its allow list, together with the address the connection actually came from.
4. If the lookup fails, the connection is closed before a single message is read.

A server therefore never serves a caller it does not recognise, and a caller never stays connected to a server it did not intend to reach.

## Allow list: who may connect

One entry per identity, each a fingerprint and an optional address:

```yaml
a1b2c3: 127.0.0.1   # this fingerprint, only from this address
d4e5f6: ~           # this fingerprint, from any address
```

An entry with an address matches only connections from it, so a stolen certificate is useless from anywhere else. An entry with `~` matches from anywhere, which is what a participant whose address moves needs. An identity absent from the list is refused. The check runs per connection, so a change takes effect on the next one without a restart. 
A file containing exactly `allow_all` accepts every fingerprint, but it exists only for tests and examples, and a real configuration lists the identities it expects.

## Routing table: who may send to whom

The allow list decides who may connect. This decides what they may do once connected, and it is consulted on every message. Three modes.

**Table**, the general form, maps each sender to the destinations it may reach. A rule matches when the fingerprint is equal and the id matches. Writing `~` as the id matches any id behind that fingerprint, which suits a component that must reach whichever endpoint a participant happens to use. The fingerprint itself is always compared exactly, and there is no wildcard for it:

```yaml
hash1:0:
- hash3:0
- hash3:1
- hash2:0
hash3:0:
- hash1:~
- hash2:1
```

**OnlyTo** accepts messages for a single destination whoever sent them and refuses everything else. A node built with `new_peers` installs this for its own identifier, which is what stops a participant from using it to reach anywhere but that node.

**AllowAll** accepts everything, for tests and examples.

## The limits and what each one bounds

Access control decides whether a sender may send. These decide how much.

| Limit | Bounds | What the sender sees |
|---|---|---|
| Rate limit | Requests per sender over time, as a budget that refills. | The request is refused, retry later. |
| Queue depth | Messages one sender may have waiting for one destination. | The send fails while that destination is behind. |
| Message size | The largest message accepted, measured as it travels. | The send is refused, with the limit and the size. |
| Delivery attempts | Retries for an undelivered message, and the delay between them. | Nothing directly, the message reaches the sender's own dead letter queue. |

**The queue cap is per sender and destination pair**, not per destination. A sender that stops draining consumes only its own quota, and others keep reaching the same destination. Its ceiling is therefore the cap multiplied by the number of identities the allow list admits.

**The rate limit is per sending identity.** A sender that exhausts its budget slows only itself.

The rate limit, the queue cap and routing are applied by the receiving broker with its own configuration, so two brokers may be configured differently and each enforces its own. Message size is checked by the sender as well, so an oversized message is refused before it reaches the wire. Delivery attempts are entirely the sending node's business.
