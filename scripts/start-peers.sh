#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

NUM_PEERS="${NUM_PEERS:-3}"
BASE_PORT="${BASE_PORT:-9101}"
SID_PREFIX="${SID_PREFIX:-peer}"
HOST="${HOST:-127.0.0.1}"

RUNTIME_DIR="$ROOT_DIR/.run/peers"
BIN_DIR="$ROOT_DIR/.run/bin"
PID_DIR="$RUNTIME_DIR/pids"
LOG_DIR="$RUNTIME_DIR/logs"
KEY_DIR="$RUNTIME_DIR/keys"
SERVER_BIN="$BIN_DIR/goaccord-server"

mkdir -p "$PID_DIR" "$LOG_DIR" "$KEY_DIR" "$BIN_DIR"

# Build once per start to pick up latest server code.
go build -o "$SERVER_BIN" "$ROOT_DIR/server"

is_running() {
  local pid="$1"
  kill -0 "$pid" 2>/dev/null
}

peer_addr() {
  local idx="$1"
  local port=$((BASE_PORT + idx - 1))
  printf '%s:%s' "$HOST" "$port"
}

for ((i=1; i<=NUM_PEERS; i++)); do
  sid="${SID_PREFIX}${i}"
  pid_file="$PID_DIR/$sid.pid"
  log_file="$LOG_DIR/$sid.log"
  key_file="$KEY_DIR/$sid-owner-key.json"
  listen_addr=":$((BASE_PORT + i - 1))"
  advertise_addr="$(peer_addr "$i")"

  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
    if [[ -n "$pid" ]] && is_running "$pid"; then
      echo "$sid already running (pid $pid)"
      continue
    fi
    rm -f "$pid_file"
  fi

  peers_csv=""
  if (( i > 1 )); then
    peers_csv="$(peer_addr 1)"
    if (( i > 2 )); then
      peers_csv=",$(peer_addr $((i-1)))"
      peers_csv="$(peer_addr 1)$peers_csv"
    fi
  fi

  cmd=(
    "$SERVER_BIN"
    -listen "$listen_addr"
    -advertise "$advertise_addr"
    -sid "$sid"
    -key "$key_file"
    -client-mode public
  )
  if [[ -n "$peers_csv" ]]; then
    cmd+=( -peers "$peers_csv" )
  fi

  nohup "${cmd[@]}" >"$log_file" 2>&1 &
  pid="$!"
  echo "$pid" > "$pid_file"
  echo "started $sid on $advertise_addr (pid $pid)"
done

echo "runtime dir: $RUNTIME_DIR"
