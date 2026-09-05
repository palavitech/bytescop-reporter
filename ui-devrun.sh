#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/ui"

echo
echo "[*] BytesCop-Reporter — UI Dev Runner"
echo

# Check Node.js
echo "[*] Checking Node.js..."

if ! command -v node >/dev/null 2>&1; then
    echo "[-] Node.js is not installed. Install Node.js 22+ via nvm or your package manager."
    exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 22 ]; then
    echo "[-] Node.js 22+ required (found $(node -v)). Update via nvm: nvm install 22"
    exit 1
fi
echo "[+] Node.js $(node -v) detected."
echo

# Install dependencies
echo "[*] Checking dependencies..."

if [ ! -d node_modules ]; then
    echo "[*] node_modules not found — running npm install..."
    npm install
    echo "[+] Dependencies installed."
else
    echo "[+] node_modules exists — skipping npm install."
fi
echo

# Start Angular dev server
echo "[*] Starting Angular dev server"
echo "[*] UI will be available at http://localhost:4200"
echo "[*] API requests proxy to http://localhost:8000 (via proxy.conf.json)"
echo "[*] Press Ctrl+C to stop."
echo

exec npx ng serve --host 0.0.0.0 -c local
