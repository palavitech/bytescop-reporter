#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo
echo "[*] BytesCop-Reporter — Flush Dev Data"
echo

# Safety check: only allow in dev environment
if [ ! -f .env ]; then
    echo "[-] .env file not found. This script is for the dev environment only."
    exit 1
fi

set -a
source .env
set +a

export DJANGO_SETTINGS_MODULE=bytescop.settings.dev
export DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:-any-dev-secret}"
export DJANGO_ALLOWED_HOSTS="${DJANGO_ALLOWED_HOSTS:-*}"
export DJANGO_DEBUG="${DJANGO_DEBUG:-true}"
export POSTGRES_HOST=localhost
export POSTGRES_DB="${POSTGRES_DB:-bytescop}"
export POSTGRES_USER="${POSTGRES_USER:-bytescop}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.dev.yml"

echo "[!] WARNING: This will permanently delete ALL data in the dev database."
echo "[!] Database: ${POSTGRES_DB} @ ${POSTGRES_HOST}"
echo "[!] This will also clear Redis, local media files, and re-run migrations."
echo
read -rp "[?] Type 'FLUSH' to confirm: " CONFIRM

if [ "$CONFIRM" != "FLUSH" ]; then
    echo "[-] Aborted."
    exit 1
fi

echo

# Step 1: Flush the database
echo "[*] Step 1/4 — Flushing database"

DB_RUNNING=$($COMPOSE ps --status running db 2>/dev/null | grep -c "db" || true)
if [ "$DB_RUNNING" -lt 1 ]; then
    echo "[-] PostgreSQL container is not running. Start it with ./api-devrun.sh first."
    exit 1
fi

$COMPOSE exec -T db psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c "
    DROP SCHEMA public CASCADE;
    CREATE SCHEMA public;
    GRANT ALL ON SCHEMA public TO ${POSTGRES_USER};
" >/dev/null 2>&1
echo "[+] Database schema dropped and recreated."

# Step 2: Flush Redis
echo "[*] Step 2/4 — Flushing Redis"

REDIS_RUNNING=$($COMPOSE ps --status running redis 2>/dev/null | grep -c "redis" || true)
if [ "$REDIS_RUNNING" -ge 1 ]; then
    $COMPOSE exec -T redis redis-cli FLUSHALL >/dev/null 2>&1
    echo "[+] Redis flushed."
else
    echo "[~] Redis not running — skipped."
fi

# Step 3: Delete local media files
echo "[*] Step 3/4 — Deleting local media files"

MEDIA_DIR="$SCRIPT_DIR/api/media"
if [ -d "$MEDIA_DIR" ]; then
    rm -rf "${MEDIA_DIR:?}"/*
    echo "[+] Media directory cleared: $MEDIA_DIR"
else
    echo "[~] No media directory found — skipped."
fi

# Step 4: Re-run migrations and seed
echo "[*] Step 4/4 — Running migrations and seed data"

cd api

.venv/bin/python manage.py migrate --no-input
echo "[+] Migrations applied."

.venv/bin/python manage.py ensure_install_state
.venv/bin/python manage.py ensure_subscription_plans
echo "[+] Seed data applied."

echo
echo "[+] Dev environment flushed. Run ./api-devrun.sh to start fresh."
