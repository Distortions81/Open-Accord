# GoAccord Design Note

## Status
This note defines the current architecture target and phased plan.

Protocol reference: `PROTOCOL.md` is the wire-level implementation target for independent clients/servers.

Date: 2026-02-10
Phase: Live-only mesh by default, with optional persistence mode.

## Status Checklist
- [x] Live-only default behavior is the default server mode. (Complete)
- [x] Owner-scoped `server_id` is enforced in startup/handshake paths. (Complete)
- [x] Groups/channels are explicit operations (`channel_create`, `group_invite`, `channel_join`, `channel_leave`, `channel_send`). (Complete)
- [x] Baseline automated coverage exists for signed delivery, cross-server relay, persist replay, and server identity proof handshake. (Complete)
- [ ] Channel role model (`owner/admin/moderator` ACLs). (Planned)
- [ ] Persistence ack/replay cursor (`since_seq` or `since_time`). (Planned)
- [ ] Persistence retention/TTL and compaction controls. (Planned)
- [ ] Optional encrypted persistence blobs at rest. (Planned)

## Goals
- Support user-to-user messaging across a network of servers.
- Support user-created groups and channels.
- Avoid central authority for user identity or server identity.
- Store as little as possible on servers.

## Non-goals (Current Phase)
- No guaranteed global offline delivery guarantees.
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
- User-sent messages are signed end-to-end at transport protocol level.
- Peer servers prove owner binding for `server_id` with owner-key signatures during handshake.

## Storage Policy
- Default mode is live-only behavior.
- Live-only server state is memory-only:
  - active client sessions
  - active peer sessions
  - short-lived message dedupe cache (TTL)
  - rate-limit/ban cache
- No durable user account storage in live mode.
- No durable message storage in live mode.

## Persistence Mode (Opt-In)
- `persistence-mode=persist` enables local SQLite-backed durable state.
- Hosted identities:
  - users can be attached to a persistence server identity
  - server can auto-host authenticated users or require pre-hosting policy
- Offline delivery:
  - messages for hosted-but-offline users are queued
  - queue is replayed at next successful login
- Durable metadata (minimal scope):
  - groups/channels observed in traffic
  - server identities seen in peer sessions
- Persistence remains local policy only, not a global authority.

## Routing Model
- Servers relay signed actions (messages, friend actions, channel actions) across peers.
- Message IDs are deduped to prevent loops.
- Delivery is best-effort to currently connected recipients.
- In persistence mode, hosted offline recipients can receive store-and-forward replay.

## Group and Channel Model (Current)
- Groups are user-created.
- Channels exist inside groups.
- Current transport supports `group` and `channel` message labels.
- Current supports channel membership, public/private channel creation, invites, join/leave, and channel fanout.
- Public channels allow any authenticated user to invite any user.
- Private channels require inviter membership; non-owner member invites require inviter-friendship with invitee.
- Full role model (owner/admin/moderator ACLs) is later work.

## Protocol Shape (Current)
- Auth flow:
  - `hello(role=user,pub_key)`
  - `challenge(nonce)`
  - `auth(pub_key,signature(login:nonce))`
  - `ok(id=login_id)`
- Direct message flow:
  - `send(id,from,to,body,pub_key,sig)`
  - `deliver(id,from,to,body,...)`
- Group/channel labels:
  - `send(...,group,channel,...)`
- Planned explicit group/channel operations:
  - `group_create`
  - `group_join`
  - `channel_create`
  - `channel_send`
  - `channel_deliver`

## Operational Limits
- Keep a configurable server memory ceiling.
  - Future flags: `--max-memory-mb`, `--cache-evict-policy`.
- Keep configurable ingress rate limits.
  - Existing examples: `--max-msgs-per-sec`, `--burst`.
- Keep a hard maximum packet size and ignore anything larger.
  - Current default: `32 KiB` serialized packet size.
- Support optional body compression (`zlib` or `none`) with bounded expansion checks.
  - Current defaults: `max_uncompressed_bytes=64 KiB`, `max_expand_ratio=64`.
  - Oversized decoded payloads are dropped.

## Capabilities (Current)
- Peers advertise capability flags during handshake (`caps`).
- Current flags include:
  - `transport` (participates in peer mesh)
  - `relay` (relays user traffic across peers)
  - `client_public` (accepts any client logins)
  - `client_private` (accepts only allowlisted clients)
  - `client_disabled` (rejects all client logins)

## Peer Policy and Abuse Handling
- Peers advertise inbound policy during handshake:
  - `max_msg_bytes`
  - `max_msgs_per_sec`
  - `burst`
- Each node enforces its own inbound policy.
- Nodes use peer-advertised max message size to avoid forwarding oversized packets.
- Nodes maintain local peer scores and temporary bans for abusive peers.

## Terminology (Network-Native)
- Use network messaging terms, not block-chain terms.
- Preferred vocabulary:
  - `relay`
  - `message` / `event`
  - `mesh` / `peer transport`
  - `sync` / `catch-up`

## Glossary
- `login_id`
Meaning: deterministic user identity (`sha256(pubkey)`).
Function: primary user address and auth identity across the mesh.
- `server_id`
Meaning: owner-scoped server identity (`owner_login_id:local_server_id`).
Function: peer identity namespace without central allocation.
- `hosted identity`
Meaning: user identity attached to a persistence server.
Function: enables optional offline queueing and replay policy.
- `mesh`
Meaning: the connected peer-to-peer transport graph.
Function: path for relaying signed events between servers.
- `caps`
Meaning: advertised capability flags in handshake.
Function: feature negotiation and behavioral gating.
- `seen` cache
Meaning: bounded cache of recently observed message IDs.
Function: dedupe and loop prevention in relay paths.

## Security Notes
- Collision risk for login IDs is treated as cryptographically negligible.
- Private keys never leave clients.
- A compromised server can drop/delay traffic; signatures prevent sender impersonation.
- For confidentiality against servers, add end-to-end encryption later.

## Protocol Evolution (Later)
- Current protocol is JSON over TCP for clarity and iteration speed.
- Later we may add an optional faster binary protocol once protocol behavior is stable.
- Binary protocol should be capability-negotiated (for example `proto_bin_v1`).
- JSON remains supported for compatibility and debugging.

## Deferred Persistence Extensions
- [ ] Ack/replay sync (`since_seq` or `since_time`). (Planned)
- [ ] Retention/TTL policies and compaction. (Planned)
- [ ] Optional encrypted blobs at rest. (Planned)
- [ ] User-controlled persistence tiers for channels/groups. (Planned)

## Immediate Implementation Priorities
- [x] Keep live-only behavior as default. (Complete)
- [x] Keep owner-scoped `server_id` model in startup/handshake. (Complete)
- [x] Expand groups/channels beyond labels into explicit operations. (Complete)
- [x] Add/extend automated tests for signed user-to-user delivery. (Complete)
- [x] Add/extend automated tests for cross-server relay. (Complete)
- [x] Add/extend automated tests for offline queue replay in persist mode. (Complete)
- [x] Add/extend automated tests for server identity proof handshake. (Complete)
