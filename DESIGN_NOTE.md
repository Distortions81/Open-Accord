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
- Peer servers should prove owner binding for `server_id` with owner-key signatures during handshake.

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

## Immediate Implementation Priorities
1. Enforce owner-scoped `server_id` model in server startup/handshake.
2. Keep live-only behavior as default and explicit.
3. Implement RAM-only groups/channels.
4. Add/extend automated tests for:
   - signed user-to-user delivery
   - cross-server relay
   - group/channel fanout
   - server identity proof handshake

## Peer Policy and Abuse Handling (Current)


## Capabilities (Current)
- Peers advertise capability flags during handshake (`caps`).
- Planned/expected flags include:
  - `transport` (participates in peer mesh)
  - `relay` (relays user traffic across peers)
  - `client_public` (accepts any client logins)
  - `client_private` (accepts only allowlisted clients)
  - `client_disabled` (rejects all client logins)
- Servers should reject client logins when `client_disabled` is set.

## Protocol Evolution (Later)
- Current protocol is JSON over TCP for clarity and iteration speed.
- Once behavior is stable, we may add an optional faster binary protocol.
  - This should be a negotiated capability (e.g., `proto_bin_v1`).
  - JSON remains supported for compatibility and debugging.
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
