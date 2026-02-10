#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

NUM_PEERS="${NUM_PEERS:-3}"
BASE_PORT="${BASE_PORT:-9101}"
SID_PREFIX="${SID_PREFIX:-peer}"
HOST="${HOST:-127.0.0.1}"

PERSIST_ENABLED="${PERSIST_ENABLED:-1}"
PERSIST_PORT="${PERSIST_PORT:-$((BASE_PORT + NUM_PEERS))}"
PERSIST_SID="${PERSIST_SID:-persist}"
PERSIST_AUTO_HOST="${PERSIST_AUTO_HOST:-true}"
PERSIST_CLIENT_MODE="${PERSIST_CLIENT_MODE:-public}"

RUNTIME_DIR="$ROOT_DIR/.run/peers"
BIN_DIR="$ROOT_DIR/.run/bin"
PID_DIR="$RUNTIME_DIR/pids"
LOG_DIR="$RUNTIME_DIR/logs"
KEY_DIR="$RUNTIME_DIR/keys"
STATE_DIR="$RUNTIME_DIR/state"
SERVER_BIN="$BIN_DIR/goaccord-server"

mkdir -p "$PID_DIR" "$LOG_DIR" "$KEY_DIR" "$BIN_DIR" "$STATE_DIR"

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

start_node() {
  local sid="$1"
  local listen_addr="$2"
  local advertise_addr="$3"
  local key_file="$4"
  local log_file="$5"
  local peers_csv="$6"
  shift 6
  local extra_args=("$@")

  local pid_file="$PID_DIR/$sid.pid"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file")"
    if [[ -n "$pid" ]] && is_running "$pid"; then
      echo "$sid already running (pid $pid)"
      return
    fi
    rm -f "$pid_file"
  fi

  local cmd=(
    "$SERVER_BIN"
    -listen "$listen_addr"
    -advertise "$advertise_addr"
    -sid "$sid"
    -key "$key_file"
  )
  if [[ -n "$peers_csv" ]]; then
    cmd+=( -peers "$peers_csv" )
  fi
  if (( ${#extra_args[@]} > 0 )); then
    cmd+=( "${extra_args[@]}" )
  fi

  nohup "${cmd[@]}" >"$log_file" 2>&1 &
  local pid="$!"
  echo "$pid" > "$pid_file"
  echo "started $sid on $advertise_addr (pid $pid)"
}

for ((i=1; i<=NUM_PEERS; i++)); do
  sid="${SID_PREFIX}${i}"
  log_file="$LOG_DIR/$sid.log"
  key_file="$KEY_DIR/$sid-owner-key.json"
  listen_addr=":$((BASE_PORT + i - 1))"
  advertise_addr="$(peer_addr "$i")"

  peers_csv=""
  if (( i > 1 )); then
    peers_csv="$(peer_addr 1)"
    if (( i > 2 )); then
      peers_csv+=",$(peer_addr $((i-1)))"
    fi
  fi

  start_node \
    "$sid" \
    "$listen_addr" \
    "$advertise_addr" \
    "$key_file" \
    "$log_file" \
    "$peers_csv" \
    -client-mode public

done

if [[ "$PERSIST_ENABLED" == "1" || "$PERSIST_ENABLED" == "true" ]]; then
  persist_addr="$HOST:$PERSIST_PORT"
  persist_log="$LOG_DIR/$PERSIST_SID.log"
  persist_key="$KEY_DIR/$PERSIST_SID-owner-key.json"
  persist_db="$STATE_DIR/$PERSIST_SID.sqlite"

  persist_peers=""
  if (( NUM_PEERS >= 1 )); then
    persist_peers="$(peer_addr 1)"
  fi

  start_node \
    "$PERSIST_SID" \
    ":$PERSIST_PORT" \
    "$persist_addr" \
    "$persist_key" \
    "$persist_log" \
    "$persist_peers" \
    -client-mode "$PERSIST_CLIENT_MODE" \
    -persistence-mode persist \
    -persist-auto-host "$PERSIST_AUTO_HOST" \
    -persistence-db "$persist_db"
fi

echo "runtime dir: $RUNTIME_DIR"
