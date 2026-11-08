#!/usr/bin/env bash
#
# run.sh
# Picks a free host port (starting from HOST_PORT or 8000, scanning up to 8100)
# and launches `docker compose up --build` with HOST_PORT set accordingly.

set -euo pipefail

START_PORT="${HOST_PORT:-8000}"
MAX_PORT=8100

is_port_free() {
  local port="$1"

  if command -v ss >/dev/null 2>&1; then
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${port}\$"; then
      return 1
    fi
    return 0
  fi

  if command -v lsof >/dev/null 2>&1; then
    if lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
      return 1
    fi
    return 0
  fi

  # Fallback: ask Python to try binding the port.
  python3 - "$port" <<'PYEOF' >/dev/null 2>&1
import socket
import sys

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", port))
except OSError:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PYEOF
  return $?
}

FREE_PORT=""
for ((port = START_PORT; port <= MAX_PORT; port++)); do
  if is_port_free "$port"; then
    FREE_PORT="$port"
    break
  fi
done

if [[ -z "$FREE_PORT" ]]; then
  echo "❌ Could not find a free port between ${START_PORT} and ${MAX_PORT}." >&2
  exit 1
fi

export HOST_PORT="$FREE_PORT"

echo ""
echo "============================================================"
echo "👉 Open your browser at http://localhost:${FREE_PORT}"
echo "============================================================"
echo ""

docker compose up --build
