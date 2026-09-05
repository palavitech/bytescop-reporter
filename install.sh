#!/usr/bin/env bash
set -euo pipefail

echo "========================================="
echo "  BytesCop-Reporter — Installation"
echo "========================================="
echo

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "[!] Error: docker is required but not installed. See https://docs.docker.com/get-docker/"; exit 1; }
if ! docker compose version >/dev/null 2>&1; then
    echo "[!] Error: docker compose plugin is required but not installed."
    echo "    Install it with: sudo apt install docker-compose"
    echo "    Or see: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check for previous installation
PREVIOUS_INSTALL=false
if [ -f .env ] || [ -d ./data/postgres ] || docker compose ps -q 2>/dev/null | grep -q .; then
    PREVIOUS_INSTALL=true
fi

if [ "$PREVIOUS_INSTALL" = true ]; then
    echo "[!] A previous BytesCop-Reporter installation was detected."
    echo
    echo "    Continuing will:"
    echo "    - Stop all running containers"
    echo "    - Remove all Docker volumes (database, Redis, UI cache)"
    echo "    - Delete the database (./data/postgres)"
    echo "    - Delete all logs (./logs)"
    echo "    - Regenerate .env with new secrets"
    echo "    - Regenerate SSL certificates"
    echo
    echo "    THIS WILL PERMANENTLY DESTROY ALL DATA."
    echo
    read -rp "[?] Are you sure you want to proceed? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "[-] Installation cancelled."
        exit 0
    fi
    echo
    echo "[*] Removing previous installation..."
    docker compose down -v 2>/dev/null || true
    # Docker creates files as root — use a container to clean up
    docker run --rm -v "$(pwd)/data:/data" -v "$(pwd)/logs:/logs" alpine sh -c "rm -rf /data/postgres /logs/*" 2>/dev/null || true
    rm -rf ./data/postgres ./logs .env ./ssl 2>/dev/null || true
    echo "[+] Previous installation removed."
    echo
fi

# Create .env from example
if [ ! -f .env ]; then
    echo "[*] Creating .env from .env.example..."
    cp .env.example .env

    # Generate a random Django secret key
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))" 2>/dev/null || openssl rand -base64 50 | tr -d '\n')
    sed -i "s|DJANGO_SECRET_KEY=changeme-generate-a-random-string|DJANGO_SECRET_KEY=${SECRET_KEY}|" .env

    # Generate a random PostgreSQL password
    PG_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))" 2>/dev/null || openssl rand -base64 24 | tr -d '\n')
    sed -i "s|POSTGRES_PASSWORD=changeme|POSTGRES_PASSWORD=${PG_PASS}|" .env

    echo "[+] Generated .env with random secrets."
    echo "[*] Edit .env to configure email (SMTP) and other settings."
    echo
fi

# Generate self-signed SSL certificate if not present
SSL_DIR="./ssl"
if [ ! -f "$SSL_DIR/bytescop.crt" ]; then
    echo "[*] Generating self-signed SSL certificate..."
    mkdir -p "$SSL_DIR"
    openssl req -x509 -nodes -days 36500 \
        -newkey rsa:2048 \
        -keyout "$SSL_DIR/bytescop.key" \
        -out "$SSL_DIR/bytescop.crt" \
        -subj "/CN=bytescop" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    echo "[+] SSL certificate generated (self-signed, 100-year expiry)."
    echo "[*] Replace ssl/bytescop.crt and ssl/bytescop.key with your own for trusted HTTPS."
    echo
fi

# Create host-mounted directories
mkdir -p ./logs ./data/postgres

# Read version
APP_VERSION=$(cat VERSION 2>/dev/null || echo "dev")
export APP_VERSION
echo "[*] Installing BytesCop-Reporter v${APP_VERSION}"
echo

# Build and start
echo "[*] Building Docker images (this may take a few minutes)..."
docker compose build

echo "[*] Starting services..."
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

echo "[*] Seeding data..."
docker compose exec -T api python manage.py ensure_subscription_plans
docker compose exec -T api python manage.py ensure_classification_entries
docker compose exec -T api python manage.py ensure_install_state

echo
echo "========================================="
echo "  [+] BytesCop-Reporter v${APP_VERSION} is running!"
echo "========================================="
echo
echo "  Open https://localhost in your browser."
echo "  (Accept the self-signed certificate warning)"
echo "  The setup wizard will guide you through creating"
echo "  your admin account and first workspace."
echo
echo "  To stop:   docker compose down"
echo "  To update: ./update.sh"
echo "  To backup: ./backup.sh"
echo
