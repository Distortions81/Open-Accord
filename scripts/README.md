# Peer Scripts

Simple local orchestration for running multiple GoAccord peers.

## Scripts
- `scripts/start-peers.sh`
  - Builds `./server` and starts a peer set in the background.
  - Starts standard transport peers plus an optional dedicated persistence peer.
  - Persists PID files, logs, owner keys, and persistence DB under `.run/peers/`.
- `scripts/stop-peers.sh`
  - Stops all peers started by `start-peers.sh`.
- `scripts/reboot-peers.sh`
  - Stops then starts peers (use after server code updates).
- `scripts/status-peers.sh`
  - Shows running/stopped state and log locations.

## Defaults
- `NUM_PEERS=3`
- `BASE_PORT=9101`
- `SID_PREFIX=peer`
- `HOST=127.0.0.1`

Persistence peer defaults:
- `PERSIST_ENABLED=1`
- `PERSIST_PORT=BASE_PORT+NUM_PEERS`
- `PERSIST_SID=persist`
- `PERSIST_AUTO_HOST=true`
- `PERSIST_CLIENT_MODE=public`

Runtime layout:
- `.run/bin/goaccord-server`
- `.run/peers/pids/*.pid`
- `.run/peers/logs/*.log`
- `.run/peers/keys/*-owner-key.json`
- `.run/peers/state/*.sqlite`

## Examples
Start default peers + persistence node:
```bash
./scripts/start-peers.sh
```

Start 5 peers at port 9201 + persistence on 9300:
```bash
NUM_PEERS=5 BASE_PORT=9201 PERSIST_PORT=9300 ./scripts/start-peers.sh
```

Disable persistence peer:
```bash
PERSIST_ENABLED=0 ./scripts/start-peers.sh
```

Reboot peers after changes:
```bash
./scripts/reboot-peers.sh
```

Stop peers:
```bash
./scripts/stop-peers.sh
```

## Policy Note
The default persistence node is intentionally permissive for local development (`persist-auto-host=true`, `client-mode=public`).
Production behavior should usually be selective/allowlisted.
