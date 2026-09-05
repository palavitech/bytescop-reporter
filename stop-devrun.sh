#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo
echo "[*] BytesCop-Reporter — Stopping Dev Environment"
echo

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.dev.yml"

# Stop Docker dev stack
RUNNING=$($COMPOSE ps --status running -q 2>/dev/null | wc -l || true)

if [ "$RUNNING" -gt 0 ]; then
    echo "[*] Stopping Docker dev stack..."
    $COMPOSE down
    echo "[+] Docker containers stopped."
else
    echo "[+] Docker dev stack is not running."
fi

# Kill any lingering Django dev server
DJANGO_PIDS=$(pgrep -f "manage.py runserver" 2>/dev/null || true)
if [ -n "$DJANGO_PIDS" ]; then
    echo "[*] Stopping Django dev server (PID: $DJANGO_PIDS)..."
    kill $DJANGO_PIDS 2>/dev/null || true
    echo "[+] Django dev server stopped."
fi

# Kill any lingering Angular dev server
NG_PIDS=$(pgrep -f "ng serve" 2>/dev/null || true)
if [ -n "$NG_PIDS" ]; then
    echo "[*] Stopping Angular dev server (PID: $NG_PIDS)..."
    kill $NG_PIDS 2>/dev/null || true
    echo "[+] Angular dev server stopped."
fi

echo
echo "[+] Dev environment stopped."
