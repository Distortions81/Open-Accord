# Open Accord

Local-first, signed messaging in Go.

Open Accord is a compact, hackable messaging stack with:
- authenticated identities (`login_id = sha256(pubkey)`)
- signed user actions
- direct messaging
- friend graph + channels
- optional SQLite-backed persistence
- both terminal and web clients

If you want something you can run, inspect, and extend in one sitting, this is it.

## Why This Repo

- Real protocol, not mock glue
- Simple transport (TCP + JSON lines)
- Strong identity model (Ed25519 signatures)
- Good local DX (single binary server + simple clients)
- Clear protocol doc: `PROTOCOL.md`

## Quick Start

Prereqs:
- Go 1.22+ (or current stable Go)

1. Start a server:

```bash
go run ./server -listen :9101
```

2. Start web client:

```bash
go run ./client-web -addr 127.0.0.1:9101
```

3. Start a second client (web or TUI) and message between identities.

TUI option:

```bash
go run ./client-tui -addr 127.0.0.1:9101
```

## What Works Today

- Auth handshake (`hello -> challenge -> auth -> ok`)
- Signed actions with replay protection (`id` dedupe)
- DM send/deliver
- End-to-end encrypted DMs (client-side envelope over signed `send`)
- Friend-handshake E2EE key exchange with Ed25519 key-binding verification
- Multi-device E2EE support (multiple verified keys per user, capped locally)
- Friend add/accept + friend updates
- Channels: create, invite, join, leave, send
- Profile set/get and cached profile cards
- Web UI friend list with copy-ID action + online status check
- Optional persistence mode with offline delivery queue for hosted users
- Peer relay across nodes
- TLS transport for node<->node and client<->node (required)
- Built-in stats endpoint/page on server (`-stats-http`)

## Repository Layout

- `server/` server implementation + tests
- `client-web/` local web UI client
- `client-tui/` terminal UI client (Bubble Tea)
- `scripts/` multi-peer local orchestration scripts
- `PROTOCOL.md` current wire protocol and packet semantics
- `DESIGN_NOTE.md` implementation context and notes
- `TEST_PLAN.md` testing checklist

## Multi-Peer Dev Setup

Start a local peer mesh (plus optional persistence node):

```bash
./scripts/start-peers.sh
```

Check status:

```bash
./scripts/status-peers.sh
```

Stop all peers:

```bash
./scripts/stop-peers.sh
```

More options: `scripts/README.md`

## Server Flags You’ll Actually Use

- `-listen` TCP listen address
- `-peers` comma-separated seed peers
- `-relay` relay signed actions between peers
- `-tls-cert` TLS cert path (auto-generated if missing, auto-rotated when older than 30 days)
- `-tls-key` TLS private key path (auto-generated if missing/rotated with cert)
- `-client-mode` `public|private|disabled`
- `-client-allow` allowlist when `client-mode=private`
- `-persistence-mode` `live|persist`
- `-persistence-db` sqlite path
- `-stats-http` enable local stats page
- `-stats-addr` stats HTTP listen address

See all options in `server/main.go`.

## Clients

Web client (`client-web`):
- browser UI for chat, friends, profiles, targets
- local polling API
- identity select/create flow

TUI client (`client-tui`):
- command-driven terminal workflow
- contact aliases and channel controls

Detailed docs:
- `client-web/README.md`
- `client-tui/README.md`

## Protocol Notes

Protocol is intentionally unversioned and pragmatic right now.
Pre-beta policy: prefer clean breaks over backward-compatibility shims when protocol/message behavior changes.
When behavior changes, update `PROTOCOL.md`, tests, and clients in lockstep.
For exact behavior, `PROTOCOL.md` is authoritative for this repo state.

## Contributing

1. Open an issue or draft a design note for non-trivial changes.
2. Keep protocol and implementation aligned (`PROTOCOL.md` + code).
3. Add/update tests in `server/main_test.go` when behavior changes.

---

Open Accord is built to be understandable and modifiable. Clone it, run it, break it, improve it.
