#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PID_DIR="$ROOT_DIR/.run/peers/pids"

if [[ ! -d "$PID_DIR" ]]; then
  echo "no pid directory: $PID_DIR"
  exit 0
fi

shopt -s nullglob
pid_files=("$PID_DIR"/*.pid)
if (( ${#pid_files[@]} == 0 )); then
  echo "no peers running"
  exit 0
fi

for pid_file in "${pid_files[@]}"; do
  sid="$(basename "$pid_file" .pid)"
  pid="$(cat "$pid_file" || true)"
  if [[ -z "$pid" ]]; then
    rm -f "$pid_file"
    continue
  fi

  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in {1..20}; do
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
    echo "stopped $sid (pid $pid)"
  else
    echo "$sid not running (stale pid $pid)"
  fi

  rm -f "$pid_file"
done
