# GoAccord Design Note

## Status
This note defines the current architecture target and phased plan.

Date: 2026-02-10
Phase: Live-only messaging network (no persistence yet)

## Goals
- Support user-to-user messaging across a network of servers.
- Support user-created groups and channels.
- Avoid central authority for user identity or server identity.
- Store as little as possible on servers.

## Non-goals (Current Phase)
- No guaranteed offline delivery.
- No durable message history.
- No central username registry.

## Identity Model
- User identity is wallet-style:
  - `login_id = sha256(public_key)`
- Clients own private keys and sign authentication/messages.
- Servers verify signatures and do not store password/account records.

## Server Identity Model
- Server identity is owner-scoped:
  - `server_id = owner_login_id:local_server_id`
- `owner_login_id` is a user login ID (hash of owner pubkey).
- `local_server_id` is chosen by that owner and only needs to be unique per owner.
- No global registry is required.

## Trust and Authentication
- User login uses challenge-response signature verification.
- User-sent messages are signed end-to-end (at transport protocol level).
- Peer servers prove owner binding for `server_id` with owner-key signatures during handshake.

## Storage Policy (Current Phase)
- Live-only network behavior.
- Server state is memory-only:
  - active client sessions
  - active peer sessions
  - short-lived message dedupe cache (TTL)
  - group/channel membership maps
- No durable user account storage.
- No durable message storage.

## Routing Model
- Servers relay messages across peers.
- Message IDs are deduped to prevent loops.
- Delivery is best-effort to currently connected recipients.

## Group and Channel Model (Current Phase)
- Groups are user-created, with creator identity recorded in memory.
- Channels exist inside groups.
- Membership and channel metadata are memory-only.
- Channel messages fan out to currently connected group members.
- On server restart, group/channel state is lost and must be recreated/rejoined.

## Protocol Shape (Current Phase)
- Auth flow:
  - `hello(role=user,pub_key)`
  - `challenge(nonce)`
  - `auth(pub_key,signature(login:nonce))`
  - `ok(id=login_id)`
- Direct message flow:
  - `send(id,from,to,body,pub_key,sig)`
  - `deliver(id,from,to,body,...)`
- Planned group/channel operations:
  - `group_create`
  - `group_join`
  - `channel_create`
  - `channel_send`
  - `channel_deliver`

## Operational Limits (Planned)
- Add a configurable server memory ceiling.
  - Example future flags: `--max-memory-mb`, `--cache-evict-policy`.
- Add a configurable ingress rate limit.
  - Example future flags: `--max-msgs-per-sec`, `--burst`.
- Add a hard maximum message size and drop anything larger.
  - Recommended default: `16 KiB` serialized packet size.
  - Behavior: if packet size exceeds max, server ignores/drops it.

## Capabilities (Current)
- Peers advertise capability flags during handshake (`caps`).
- Current flags include:
  - `transport` (participates in peer mesh)
  - `relay` (relays user traffic across peers)
  - `client_public` (accepts any client logins)
  - `client_private` (accepts only allowlisted clients)
  - `client_disabled` (rejects all client logins)
- Servers reject client logins when `client_disabled` is set.

## Peer Policy and Abuse Handling (Current)
- Peers advertise inbound policy during handshake:
  - `max_msg_bytes`
  - `max_msgs_per_sec`
  - `burst`
- Each node enforces its own inbound policy.
- Nodes use peer-advertised max message size to avoid forwarding packets that exceed a peer's declared limit.
- Nodes maintain local peer scores and temporary bans for abusive peers.
  - Invalid/malformed peer traffic increases score.
  - At threshold, peer is temporarily banned.
  - Bans are local cache state (memory only), not globally authoritative.

## Terminology (Network-Native)
- Avoid block-chain terms in protocol and code naming.
- Preferred vocabulary:
  - `relay` (not `block-relay`)
  - `message` / `event` (not `tx`)
  - `mesh` / `peer transport` (not `block network`)
  - `sync` / `catch-up` (not `chain sync`)
- If we later add outbound peer slot classes, keep names network-specific, for example:
  - `mesh_relay`
  - `mesh_probe`
  - `addr_probe`

## Glossary
- `login_id`
Meaning: deterministic user identity (`sha256(pubkey)`).
Function: primary user address and auth identity across the mesh.
- `server_id`
Meaning: owner-scoped server identity (`owner_login_id:local_server_id`).
Function: peer identity namespace without central allocation.
- `owner_login_id`
Meaning: login identity derived from the server owner's key.
Function: cryptographic root used to prove control of `server_id`.
- `mesh`
Meaning: the connected peer-to-peer transport graph.
Function: path for relaying signed events between servers.
- `peer`
Meaning: another server connected over transport.
Function: exchanges relay traffic, peer addresses, capabilities, and limits.
- `seed peer`
Meaning: bootstrap peer configured manually.
Function: initial entry point into the mesh and address discovery.
- `known address`
Meaning: cached peer network endpoint (`host:port`).
Function: candidate set for future outbound peer connections.
- `caps`
Meaning: advertised capability flags in handshake.
Function: feature negotiation and behavioral gating.
- `transport` capability
Meaning: node participates in mesh connectivity.
Function: allows address exchange and peer session operation.
- `relay` capability
Meaning: node relays signed message traffic to peers.
Function: controls whether node participates in event propagation.
- `client_mode`
Meaning: server policy for direct client access (`public|private|disabled`).
Function: gates which clients may authenticate to the server.
- `client_allow`
Meaning: allowlist of `login_id` values (private mode only).
Function: restricts client entry to approved identities.
- `max_msg_bytes`
Meaning: max accepted serialized packet size.
Function: defensive limit; oversized packets are dropped.
- `max_msgs_per_sec`
Meaning: ingress packet rate limit per connection.
Function: bounds abuse and accidental overload.
- `burst`
Meaning: short-term packet allowance above steady rate.
Function: allows brief spikes without immediate throttling.
- `seen` cache
Meaning: bounded cache of recently observed message IDs.
Function: dedupe and loop prevention in relay paths.
- `peer score`
Meaning: local misbehavior score for a peer address.
Function: drives temporary bans for malformed or invalid traffic.
- `peer ban`
Meaning: temporary local deny interval for a peer.
Function: protects local node without global trust assumptions.

## Security Notes
- Collision risk for login IDs is treated as cryptographically negligible.
- Private keys never leave clients.
- A compromised server can drop/delay traffic; signatures prevent sender impersonation.
- For confidentiality against servers, add end-to-end encryption in a later phase.

## Deferred Phase: Optional Persistence
Persistence is intentionally deferred.

Later, users may run personal persistence servers with opt-in behavior:
- server mode: `persist`
- store-and-forward for identities/groups hosted by that server
- ack/replay sync (`since_seq` or `since_time`)
- retention/TTL policies
- optional encrypted message blobs at rest

## Protocol Evolution (Later)
- Current protocol is JSON over TCP for clarity and iteration speed.
- Once behavior is stable, we may add an optional faster binary protocol.
  - This should be a negotiated capability (e.g., `proto_bin_v1`).
  - JSON remains supported for compatibility and debugging.

## Immediate Implementation Priorities
1. Enforce owner-scoped `server_id` model in server startup/handshake.
2. Keep live-only behavior as default and explicit.
3. Implement RAM-only groups/channels.
4. Add/extend automated tests for:
   - signed user-to-user delivery
   - cross-server relay
   - group/channel fanout
   - server identity proof handshake
