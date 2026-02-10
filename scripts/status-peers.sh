#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PID_DIR="$ROOT_DIR/.run/peers/pids"
LOG_DIR="$ROOT_DIR/.run/peers/logs"

if [[ ! -d "$PID_DIR" ]]; then
  echo "no peers started"
  exit 0
fi

shopt -s nullglob
for pid_file in "$PID_DIR"/*.pid; do
  sid="$(basename "$pid_file" .pid)"
  pid="$(cat "$pid_file" || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "$sid: running (pid $pid)"
  else
    echo "$sid: stopped"
  fi
  log_file="$LOG_DIR/$sid.log"
  if [[ -f "$log_file" ]]; then
    echo "  log: $log_file"
  fi
done
