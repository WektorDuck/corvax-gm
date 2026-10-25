#!/bin/sh
set -eu

DB="/app/Website/DataBase/database.db"
SEED="/app/seed/database.db"

if [ ! -f "$DB" ]; then
    echo "Инициализация SQLite из исходной базы..."
    mkdir -p "$(dirname "$DB")"
    cp "$SEED" "$DB"
fi

exec npm run start:all
