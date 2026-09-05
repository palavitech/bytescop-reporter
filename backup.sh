#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="bytescop-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

mkdir -p "${BACKUP_PATH}"

echo "========================================="
echo "  BytesCop-Reporter — Backup"
echo "========================================="
echo

# 1. Database dump
echo "Dumping PostgreSQL database..."
docker compose exec -T db pg_dump \
    -U "${POSTGRES_USER:-bytescop}" \
    "${POSTGRES_DB:-bytescop}" \
    | gzip > "${BACKUP_PATH}/database.sql.gz"
echo "  → ${BACKUP_PATH}/database.sql.gz"

# 2. Media files
echo "Backing up media files..."
docker compose cp api:/app/media "${BACKUP_PATH}/media" 2>/dev/null || echo "  (no media files)"

# 3. Environment config
echo "Backing up configuration..."
cp .env "${BACKUP_PATH}/.env" 2>/dev/null || true

echo
echo "========================================="
echo "  Backup complete!"
echo "========================================="
echo "  Location: ${BACKUP_PATH}"
echo "  Size:     $(du -sh "${BACKUP_PATH}" | cut -f1)"
echo
echo "  To restore:"
echo "    1. Stop services:  docker compose down"
echo "    2. Restore .env:   cp ${BACKUP_PATH}/.env .env"
echo "    3. Start database: docker compose up -d db"
echo "    4. Restore DB:     gunzip -c ${BACKUP_PATH}/database.sql.gz | docker compose exec -T db psql -U bytescop bytescop"
echo "    5. Restore media:  docker compose cp ${BACKUP_PATH}/media api:/app/media"
echo "    6. Start all:      docker compose up -d"
echo
