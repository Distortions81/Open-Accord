# Open Accord Implementation Overview

Date: 2026-02-10

This is a brief technical snapshot of the current system behavior and architecture.

## 1) High-level architecture

- `server/`: TCP JSON-line message server with user auth, signed action validation, relay, and optional persistence.
- `client-web/`: local web app process that connects to server as a signed user client and exposes browser APIs/UI.
- `client-tui/`: terminal client (Bubble Tea) that connects to server as a signed user client.
- `PROTOCOL.md`: wire-level packet semantics.

Identity model:
- `login_id = sha256(pubkey)` (Ed25519 keypairs).
- User actions are signed.
- Server verifies signatures and deduplicates message IDs.

## 2) Core protocol/runtime behavior

Implemented message classes:
- Direct messaging: `send` -> `deliver`
- Friend graph: `friend_add`, `friend_accept`, friend updates/requests
- Channels/servers: `channel_create`, `group_invite`, `channel_join`, `channel_leave`, `channel_send`
- Profiles: `profile_set`, `profile_get`, `profile_data`
- Presence: `presence_keepalive`, `presence_get`, `presence_data`
- Ping/pong path for liveness/RTT metadata

Transport/security:
- Auth handshake (`hello/challenge/auth/ok`)
- Signed action verification
- Replay protection via seen-ID cache
- Optional compression with safety bounds

## 3) Server status

Current server supports:
- User session management
- Peer mesh relay across servers
- Channel membership/invite enforcement
- Presence snapshots
- Optional SQLite persistence mode (hosted users + offline queue)
- Stats HTTP page

Recent reliability work:
- Peer manager now attempts multiple dial candidates per cycle for faster mesh recovery.
- Invite handling now bootstraps missing channel state on peers so cross-peer invites are not dropped when channel metadata arrives out of order.

## 4) Web UI status

Current web UX:
- Friends + profile card/info action
- Servers/channels list with invites
- Presence controls
- Thread-scoped chat view (not one global mixed chat)
  - Active DM thread only, or active server/channel thread only
- Unread badges:
  - DMs: red circular badge with white count on friend rows
  - Channels: red badge per channel
  - Servers: aggregated unread count across that server’s channels

Context behavior:
- Clicking friend opens DM context
- Clicking server/channel switches group context
- Chat title reflects current context (`<nickname> direct message` or `<group>/<channel>`)

## 5) TUI status

Current TUI includes:
- DM/friend/profile/channel/presence command set
- Invite management commands (`/invites`, `/invite-accept`)
- Server/channel listing (`/servers`)
- Contextual chat title inside the chat box
- Context-scoped viewing behavior (no unconditional all-thread mixing)
- Reconnect loop with backoff instead of immediate exit on transient disconnect

Persistence parity with web:
- TUI now persists UI state to `<profile>.ui.json`
  - known servers/channels
  - last chat context (DM target or group/channel)
- Restores that state on startup.

## 6) Reconnection behavior (clients)

`client-web`:
- Detects socket loss, reconnects with backoff
- Rebinds connection/event loop
- Republishes profile and presence on reconnect
- Refreshes profile/presence for known contacts

`client-tui`:
- Similar reconnect loop with backoff
- Does not reconnect on intentional exit (`/quit`, Ctrl+C, switch identity)
- Restores active session behavior after reconnect

## 7) Known practical caveats

- Some UX behavior still differs between web and TUI (interaction style), even when protocol features match.
- Thread behavior and unread counters are implemented in web UI; TUI uses command/panel flows and is still evolving toward full UX parity.
- Persistence guarantees depend on server mode (`live` vs `persist`).
