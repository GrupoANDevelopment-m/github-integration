#!/bin/bash
# Goodware v3.0 — Restore script
set -e
BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup.tar.gz>"
    exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop service (if running)
systemctl stop goodware 2>/dev/null || true

# Extract
TMP_DIR=$(mktemp -d)
tar -xzf "$BACKUP_FILE" -C "$TMP_DIR"

# Restore
cp "$TMP_DIR"/*/goodware.db data/
cp -r "$TMP_DIR"/*/keys/ keys/ 2>/dev/null || true
cp -r "$TMP_DIR"/*/models/ models/ 2>/dev/null || true
cp -r "$TMP_DIR"/*/config/ config/ 2>/dev/null || true

rm -rf "$TMP_DIR"
echo "Restored from $BACKUP_FILE"

# Restart
systemctl start goodware 2>/dev/null || true
