#!/usr/bin/env bash
set -euo pipefail

CURRENT_VERSION=$(cat VERSION 2>/dev/null || echo "unknown")

echo "========================================="
echo "  BytesCop-Reporter — Update"
echo "  Current version: v${CURRENT_VERSION}"
echo "========================================="
echo

# Fetch latest tags from remote
echo "[*] Checking for updates..."
git fetch --tags --quiet

# Determine target version
TARGET_TAG="${1:-}"
CODE_UPDATE_NEEDED=false

if [ -z "$TARGET_TAG" ]; then
    # No argument — find the latest release tag
    LATEST_TAG=$(git tag -l 'v*' --sort=-version:refname | head -n 1)

    if [ -z "$LATEST_TAG" ]; then
        echo "[!] No release tags found. Are you on the right remote?"
        echo "    You can specify a branch or tag manually: ./update.sh v1.2.0"
        exit 1
    fi

    TARGET_TAG="$LATEST_TAG"

    if [ "$LATEST_TAG" != "v${CURRENT_VERSION}" ]; then
        CODE_UPDATE_NEEDED=true
        echo "[*] New version available: ${LATEST_TAG} (current: v${CURRENT_VERSION})"
        read -rp "[?] Update to ${LATEST_TAG}? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            echo "[-] Update cancelled."
            exit 0
        fi
    else
        echo "[i] Code is already at the latest version (v${CURRENT_VERSION})."
    fi
else
    # Argument provided — validate it exists
    if ! git rev-parse "$TARGET_TAG" >/dev/null 2>&1; then
        echo "[!] Tag or ref '${TARGET_TAG}' not found."
        echo "    Available versions:"
        git tag -l 'v*' --sort=-version:refname | head -n 10 | sed 's/^/      /'
        exit 1
    fi

    if [ "$TARGET_TAG" != "v${CURRENT_VERSION}" ]; then
        CODE_UPDATE_NEEDED=true
    else
        echo "[i] Code is already at ${TARGET_TAG}."
    fi
fi

# ---------------------------------------------------------------------------
# Detect whether services are deployed and running
# ---------------------------------------------------------------------------
SERVICES_RUNNING=false
if docker compose ps --status running -q 2>/dev/null | grep -q .; then
    SERVICES_RUNNING=true
    echo "[i] Docker services are running."
else
    echo "[i] Docker services are not running."
fi

# ---------------------------------------------------------------------------
# Decide what to do
# ---------------------------------------------------------------------------
if [ "$CODE_UPDATE_NEEDED" = false ] && [ "$SERVICES_RUNNING" = true ]; then
    echo "[+] Already running the latest version (v${CURRENT_VERSION}) and all services are up. Nothing to do."
    exit 0
fi

echo

# ---------------------------------------------------------------------------
# Code update (backup + checkout) — only when version changed
# ---------------------------------------------------------------------------
if [ "$CODE_UPDATE_NEEDED" = true ]; then
    echo "[*] Creating pre-update backup..."
    ./backup.sh

    echo
    echo "[*] Updating code to ${TARGET_TAG}..."
    git checkout "$TARGET_TAG"
else
    echo "[i] Skipping backup and code checkout — already at ${TARGET_TAG}."
fi

# ---------------------------------------------------------------------------
# Build, deploy, migrate, seed — always runs if we got this far
# ---------------------------------------------------------------------------
APP_VERSION=$(cat VERSION 2>/dev/null || echo "dev")
export APP_VERSION

echo "[*] Building Docker images (v${APP_VERSION})..."
docker compose build

if [ "$SERVICES_RUNNING" = true ]; then
    echo "[*] Restarting services..."
else
    echo "[*] Starting services..."
fi
docker compose up -d

echo "[*] Waiting for database to be ready..."
retries=0
max_retries=30
until docker compose exec -T db pg_isready -U "${POSTGRES_USER:-bytescop}" >/dev/null 2>&1; do
    retries=$((retries + 1))
    if [ "$retries" -ge "$max_retries" ]; then
        echo "[!] Error: database did not become ready in time."
        exit 1
    fi
    sleep 2
done
echo "[+] Database is ready."

echo "[*] Running database migrations..."
docker compose exec -T api python manage.py migrate --no-input

echo "[*] Seeding permissions and plans..."
docker compose exec -T api python manage.py seed_permissions
docker compose exec -T api python manage.py ensure_subscription_plans
docker compose exec -T api python manage.py ensure_classification_entries

echo
echo "========================================="
echo "  [+] BytesCop-Reporter v${APP_VERSION} is ready!"
echo "========================================="
echo
if [ "$CODE_UPDATE_NEEDED" = true ]; then
    echo "  To roll back: ./update.sh v${CURRENT_VERSION}"
    echo
fi
