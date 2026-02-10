# GoAccord Protocol (Current)

## Scope
This document defines the current wire protocol implemented by `server/main.go`.
If code and document diverge, code behavior wins until this document is updated.

Transport:
- TCP
- JSON objects, one packet per line (`\n` terminated)
- UTF-8 JSON text

## Compatibility Policy
- Protocol is currently unversioned at packet level.
- Backward-compatible changes:
  - adding optional fields
  - adding new packet types that old nodes can ignore
- Breaking changes require coordinated updates to this document and code.

## Identity Primitives
- User identity:
  - `login_id = hex(sha256(pubkey_bytes))`
- Server identity:
  - `server_id = owner_login_id:sid`

## Signature Payloads
User auth challenge signature payload:
- `"login:" + nonce`

Server identity signature payload:
- `"server:" + server_id`

Signed action payload (JSON object):
```json
{
  "type": "...",
  "id": "...",
  "from": "...",
  "to": "...",
  "body": "...",
  "compression": "none",
  "usize": 0,
  "group": "...",
  "channel": "...",
  "public": false
}
```
Notes:
- `to/body/group/channel/public` are omitted when empty/false.
- Signature verification requires `from == sha256(pub_key)`.

## Packet Envelope
Common fields:
- `type` string (required)
- `role` string (`user|server` for hello)
- `id` string
- `from` string
- `to` string
- `body` string
- `compression` string (`none` or `zlib`)
- `usize` number (uncompressed size, required when compressed)
- `group` string
- `channel` string
- `public` bool
- `origin` string
- `nonce` string
- `pub_key` string (base64 Ed25519 public key)
- `sig` string (base64 Ed25519 signature)
- `listen` string (`host:port`)
- `addrs` array of addresses
- `max_msg_bytes` number
- `max_msgs_per_sec` number
- `burst` number
- `caps` array of strings

## Connection Handshake
### User
1. Client -> server: `hello(role=user,pub_key)`
2. Server -> client: `challenge(nonce)`
3. Client -> server: `auth(pub_key,sig(login:nonce))`
4. Server -> client: `ok(id=login_id)` or `error`

### Peer
1. Initiator -> peer: `hello(role=server,id,pub_key,sig,listen,limits,caps)`
2. Receiver verifies server identity proof.
3. Receiver -> initiator: `ok(id,pub_key,sig,listen,limits,caps)` or `error`
4. Peers exchange `getaddr`/`addr` and relay signed actions.

## Packet Types
### Core
- `hello`
- `challenge`
- `auth`
- `ok`
- `error`
- `getaddr`
- `addr`

### Signed action packets (must include `id,from,pub_key,sig`)
- `send`
- `friend_add`
- `friend_accept`
- `channel_create`
- `channel_invite`
- `channel_join`
- `channel_leave`
- `channel_send`

### Server-generated notifications
- `deliver`
- `channel_deliver`
- `friend_request`
- `friend_update`
- `channel_update`
- `channel_joined`
- `channel_invite` (also used as server notification)

## Action Semantics
### `send`
- Required: `to`, `body`
- Behavior: direct user-to-user delivery (`deliver`).

### Friend model
- `friend_add`:
  - requester indicates intent to friend `to`.
  - if reciprocal request already exists, friendship is established.
  - target receives `friend_request` (or both receive `friend_update` if mutual).
- `friend_accept`:
  - accept pending request from `to` -> `from` direction.
  - on success both users receive `friend_update`.

### Channel model
Channel key is `(group, channel)`.

- `channel_create`:
  - required: `group`, `channel`
  - creator becomes member
  - `public=true` creates/marks channel as public
- `channel_invite`:
  - required: `to`, `group`, `channel`
  - invite rules:
    - public channel: any authenticated user may invite anyone
    - private channel: inviter must be member
    - private channel and inviter is non-owner member: inviter must be friends with invitee
- `channel_join`:
  - required: `group`, `channel`
  - allowed if:
    - already member, or
    - channel is public, or
    - user has invite
- `channel_leave`:
  - required: `group`, `channel`
  - removes membership if present
- `channel_send`:
  - required: `group`, `channel`, `body`
  - sender must be member
  - server fans out `channel_deliver` to members

## Relay Rules
- Nodes relay signed action packets when local relay is enabled.
- Nodes relay only to peers advertising `relay` capability.
- Dedupe cache (`id`) prevents loops.

## Validation Rules
Signed action packets are dropped if:
- type is not one of signed action types
- missing required fields for packet type
- signature invalid
- duplicate `id` seen

## Policy and Limits
Defaults:
- `max_msg_bytes`: 32768
- `max_uncompressed_bytes`: 65536
- `max_expand_ratio`: 64
- `max_msgs_per_sec`: 50
- `burst`: 100
- `max_seen`: 20000
- `max_known_addrs`: 5000
- `known_addr_ttl`: 30m
- peer ban score threshold: 20
- peer ban duration: 10m

## Persistence Mode
`persistence-mode=persist` enables local SQLite-backed state.
Current persisted scope includes:
- hosted users
- queued direct deliveries for hosted offline users
- observed group/channel metadata
- observed server metadata

Note:
- offline queue/replay currently targets direct-style delivery payloads.

## Planned Extensions
- explicit protocol version negotiation
- richer channel roles/ACLs
- ack/replay cursor protocol (`since_seq` / `since_time`)
- capability-negotiated binary transport
