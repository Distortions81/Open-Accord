# Peer Scripts

Simple local orchestration for running multiple GoAccord peers.

## Scripts
- `scripts/start-peers.sh`
  - Builds `./server` and starts a peer set in the background.
  - Persists PID files, logs, and per-peer owner keys under `.run/peers/`.
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

Runtime layout:
- `.run/bin/goaccord-server`
- `.run/peers/pids/*.pid`
- `.run/peers/logs/*.log`
- `.run/peers/keys/*-owner-key.json`

## Examples
Start default 3 peers:
```bash
./scripts/start-peers.sh
```

Start 5 peers at port 9201:
```bash
NUM_PEERS=5 BASE_PORT=9201 ./scripts/start-peers.sh
```

Reboot peers after changes:
```bash
./scripts/reboot-peers.sh
```

Stop peers:
```bash
./scripts/stop-peers.sh
```
