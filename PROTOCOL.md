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
- Breaking changes require:
  - update this document
  - coordinated implementation update
  - migration note in release/commit message

## Identity Primitives
- User identity:
  - `login_id = hex(sha256(pubkey_bytes))`
- Server identity:
  - `server_id = owner_login_id:sid`

Signatures:
- User auth challenge signature payload: `"login:" + nonce`
- Server identity signature payload: `"server:" + server_id`
- User message signature payload is JSON of:
  - `{"type":"send","id":"...","from":"...","to":"...","body":"..."}`

Important:
- `group` and `channel` are currently NOT part of message signature payload.

## Packet Envelope
All packets are JSON objects. Common fields:

- `type` string: packet type (required)
- `id` string: message or identity id (type-dependent)
- `from` string: sender `login_id` (type-dependent)
- `to` string: recipient `login_id` (type-dependent)
- `body` string: message body or error text
- `group` string: optional group label
- `channel` string: optional channel label
- `origin` string: server id that performed local delivery/persistence operation
- `pub_key` string: base64-encoded Ed25519 public key
- `sig` string: base64-encoded Ed25519 signature

Peer/session fields:
- `role` string: `user` or `server`
- `nonce` string: login challenge nonce
- `listen` string: advertised peer `host:port`
- `addrs` array: peer address list
- `max_msg_bytes` number
- `max_msgs_per_sec` number
- `burst` number
- `caps` array of strings

## Packet Types

### `hello`
First packet on a connection.

User hello:
```json
{"type":"hello","role":"user","pub_key":"<base64>"}
```

Server hello:
```json
{
  "type":"hello",
  "role":"server",
  "id":"<server_id>",
  "pub_key":"<base64 owner pubkey>",
  "sig":"<base64 sig over server:server_id>",
  "listen":"<host:port>",
  "max_msg_bytes":16384,
  "max_msgs_per_sec":50,
  "burst":100,
  "caps":["transport","relay","client_public"]
}
```

### `challenge`
Server -> user login challenge:
```json
{"type":"challenge","nonce":"<opaque>"}
```

### `auth`
User -> server auth response:
```json
{"type":"auth","pub_key":"<base64>","sig":"<base64 sig over login:nonce>"}
```

### `ok`
Generic success response.

User auth success:
```json
{"type":"ok","id":"<login_id>","body":"authenticated"}
```

Server peer-accept success:
```json
{
  "type":"ok",
  "id":"<server_id>",
  "body":"peer accepted",
  "pub_key":"<base64 owner pubkey>",
  "sig":"<base64 sig over server:server_id>",
  "listen":"<host:port>",
  "max_msg_bytes":16384,
  "max_msgs_per_sec":50,
  "burst":100,
  "caps":["transport","relay","client_public"]
}
```

### `error`
Generic failure response:
```json
{"type":"error","body":"<reason>"}
```

### `send`
Signed user message (user->server and server->server relay):
```json
{
  "type":"send",
  "id":"<message_id>",
  "from":"<sender_login_id>",
  "to":"<recipient_login_id>",
  "body":"<text>",
  "group":"<optional>",
  "channel":"<optional>",
  "pub_key":"<base64 sender pubkey>",
  "sig":"<base64 signature>"
}
```

### `deliver`
Delivered message (server -> user):
```json
{
  "type":"deliver",
  "id":"<message_id>",
  "from":"<sender_login_id>",
  "to":"<recipient_login_id>",
  "body":"<text>",
  "group":"<optional>",
  "channel":"<optional>",
  "origin":"<server_id>",
  "pub_key":"<base64 sender pubkey>",
  "sig":"<base64 signature>"
}
```

### `getaddr`
Peer address request:
```json
{"type":"getaddr"}
```

### `addr`
Peer address advertisement:
```json
{"type":"addr","addrs":["host1:port","host2:port"]}
```

## State Machines

### User Session Flow
1. Client sends `hello(role=user, pub_key)`.
2. Server replies `challenge(nonce)`.
3. Client sends `auth(pub_key, sig(login:nonce))`.
4. Server verifies signature and policy, then sends `ok(id=login_id)`.
5. Client may send `send` packets.
6. Server may send `deliver` packets asynchronously.

### Peer Session Flow
1. Initiator sends `hello(role=server, id, pub_key, sig, listen, limits, caps)`.
2. Receiver verifies server identity proof.
3. Receiver replies `ok(...)` with its own identity proof and policy.
4. Both sides exchange `getaddr` / `addr` and relay `send` packets.

## Validation and Enforcement Rules

Connection-level:
- First packet MUST be `hello`; otherwise server returns `error` and closes.
- Packet size above local `max_msg_bytes` is ignored/dropped.
- Packet rate above local limiter is ignored/dropped.

User auth:
- `auth.pub_key` must be valid Ed25519 public key.
- `login_id` must match `sha256(pub_key)`.
- Signature must verify over `login:nonce`.

Message acceptance (`send`):
- Required non-empty fields: `id`, `from`, `to`, `body`.
- `from` must match authenticated user for user sessions.
- Signature must verify and pubkey-derived login must equal `from`.
- Duplicate `id` values are dropped by dedupe cache.

Relay behavior:
- Nodes relay only when local `relay` is enabled.
- Forwarding to peers is limited to peers advertising `relay` capability.
- Forwarding skips peers where serialized packet exceeds peer-advertised `max_msg_bytes`.

Peer misbehavior handling:
- Unknown/malformed/invalid peer packets increase local peer score.
- Score threshold triggers temporary local ban.

## Capabilities and Policy Fields

Current capability flags:
- `transport`
- `relay`
- `client_public`
- `client_private`
- `client_disabled`

Policy fields exchanged in peer hello/ok:
- `max_msg_bytes`
- `max_msgs_per_sec`
- `burst`

Interpretation:
- Policies are advisory for remote senders and enforced locally per node.

## Client Access Modes

Server setting `client-mode`:
- `public`: allow any authenticated user.
- `private`: allow only users in server allowlist.
- `disabled`: reject all user logins.

## Persistence Mode Semantics

Server setting `persistence-mode`:
- `live` (default): no durable user message state.
- `persist`: SQLite-backed durable state enabled.

Persist mode behavior:
- Authenticated users can be hosted identities:
  - auto-host if `persist-auto-host=true`
  - otherwise must already exist in hosted set
- Messages to hosted offline recipients are queued.
- Queued messages are replayed on next login (`deliver` packets).
- Group/channel labels and seen peer server identities may be stored.

## Error Behaviors
Common `error.body` values include:
- `first packet must be hello`
- `auth failed: ...`
- `client access not allowed by this server`
- `unknown role`
- `invalid server identity proof`
- `peer temporarily banned`
- `duplicate peer id`

## Resource Limits (Current Defaults)
- `max_msg_bytes`: 16384
- `max_msgs_per_sec`: 50
- `burst`: 100
- `max_seen`: 20000
- `max_known_addrs`: 5000
- `known_addr_ttl`: 30m
- peer ban score threshold: 20
- peer ban duration: 10m

## Planned Extensions
- Explicit group/channel operations (`group_create`, `group_join`, `channel_create`, `channel_send`).
- Capability-negotiated binary transport (for example `proto_bin_v1`) after protocol stabilizes.
- Explicit packet-level protocol version negotiation.
