#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load .env for database credentials
if [ ! -f .env ]; then
    echo "[-] .env file not found. Run ./install.sh first or create .env from .env.example."
    exit 1
fi
set -a
source .env
set +a

# Common env vars for Django
export DJANGO_SETTINGS_MODULE=bytescop.settings.dev
export DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:-any-dev-secret}"
export DJANGO_ALLOWED_HOSTS="${DJANGO_ALLOWED_HOSTS:-*}"
export DJANGO_DEBUG="${DJANGO_DEBUG:-true}"
export POSTGRES_HOST=localhost
export POSTGRES_DB="${POSTGRES_DB:-bytescop}"
export POSTGRES_USER="${POSTGRES_USER:-bytescop}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
export CELERY_BROKER_URL="redis://localhost:6379/0"
export CELERY_RESULT_BACKEND="redis://localhost:6379/0"

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.dev.yml"

echo
echo "[*] BytesCop-Reporter — API Dev Runner"
echo

# Step 1: Infrastructure (Docker)
echo "[*] Step 1/3 — Starting infrastructure (PostgreSQL, Redis, Celery)"

DB_RUNNING=$($COMPOSE ps --status running db 2>/dev/null | grep -c "db" || true)
REDIS_RUNNING=$($COMPOSE ps --status running redis 2>/dev/null | grep -c "redis" || true)

if [ "$DB_RUNNING" -ge 1 ] && [ "$REDIS_RUNNING" -ge 1 ]; then
    echo "[+] Docker dev stack is already running — skipping."
else
    echo "[*] Docker dev stack not running. Starting containers..."
    $COMPOSE up -d
    echo "[+] Docker containers started."

    echo "[*] Waiting for PostgreSQL to accept connections..."
    retries=0
    max_retries=30
    until $COMPOSE exec -T db pg_isready -U "${POSTGRES_USER}" >/dev/null 2>&1; do
        retries=$((retries + 1))
        if [ "$retries" -ge "$max_retries" ]; then
            echo "[-] PostgreSQL did not become ready after ${max_retries} attempts."
            exit 1
        fi
        sleep 2
    done
    echo "[+] PostgreSQL is ready."
fi
echo

# Step 2: Migrations & Seed
echo "[*] Step 2/3 — Running database migrations and seed data"

if [ ! -f api/.venv/bin/python ]; then
    echo "[-] Python venv not found at api/.venv/. Create it first:"
    echo "    cd api && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi

cd api

echo "[*] Running migrations..."
.venv/bin/python manage.py migrate --no-input
echo "[+] Migrations applied."

echo "[*] Seeding install state and subscription plans..."
.venv/bin/python manage.py ensure_install_state
.venv/bin/python manage.py ensure_subscription_plans
echo "[+] Seed data applied."
echo

# Step 3: Start API
echo "[*] Step 3/3 — Starting Django development server"
echo "[*] API will be available at http://localhost:8000"
echo "[*] Press Ctrl+C to stop."
echo

exec .venv/bin/python manage.py runserver 0.0.0.0:8000
