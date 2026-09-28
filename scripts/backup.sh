#!/bin/bash
# Goodware v3.0 — Backup script
set -e
BACKUP_DIR="${BACKUP_DIR:-/var/backups/goodware}"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/goodware_$DATE"

mkdir -p "$BACKUP_PATH"

# Backup database
cp data/goodware.db "$BACKUP_PATH/"
# Backup keys
cp -r keys/ "$BACKUP_PATH/keys/" 2>/dev/null || true
# Backup models
cp -r models/ "$BACKUP_PATH/models/" 2>/dev/null || true
# Backup config
cp -r config/ "$BACKUP_PATH/config/" 2>/dev/null || true
# Backup logs
cp -r logs/ "$BACKUP_PATH/logs/" 2>/dev/null || true

# Create tarball
tar -czf "$BACKUP_DIR/goodware_$DATE.tar.gz" -C "$BACKUP_DIR" "goodware_$DATE"
rm -rf "$BACKUP_PATH"

echo "Backup saved to $BACKUP_DIR/goodware_$DATE.tar.gz"
ls -lh "$BACKUP_DIR/goodware_$DATE.tar.gz"

# Cleanup old backups (keep last 30)
find "$BACKUP_DIR" -name "goodware_*.tar.gz" -mtime +30 -delete 2>/dev/null || true
