#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_NAME="${A2Z_DB_NAME:-opsatlas_dev}"
[[ "$DB_NAME" =~ ^opsatlas_[a-z0-9_]+$ ]] || { echo "A2Z_DB_NAME must start with opsatlas_ and contain only lowercase letters, digits, underscores" >&2; exit 2; }
[[ -z "${PGSERVICE:-}${PGSERVICEFILE:-}" ]] || { echo "PGSERVICE is not accepted by the local-only bootstrap." >&2; exit 2; }
case "${PGHOST:-localhost}" in localhost|127.0.0.1|::1) ;; *) echo "Refusing non-loopback PGHOST." >&2; exit 2 ;; esac
case "${PGHOSTADDR:-}" in ''|127.*|::1) ;; *) echo "Refusing non-loopback PGHOSTADDR." >&2; exit 2 ;; esac
command -v psql >/dev/null && command -v createdb >/dev/null || { echo "Install PostgreSQL client tools first." >&2; exit 2; }
EXISTS="$(psql -X -d postgres -Atqc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'")"
if [[ "$EXISTS" == "1" ]]; then
  echo "Refusing to modify existing database '$DB_NAME'. Choose a new name or perform a reviewed migration." >&2
  exit 3
fi
createdb --template=template0 "$DB_NAME"
psql -X -v ON_ERROR_STOP=1 -d "$DB_NAME" -f "$ROOT/database/schema.sql"
echo "Created empty schema in '$DB_NAME'. No synthetic rows were inserted."
echo "For demos only, set A2Z_DB_NAME=opsatlas_demo and run scripts/db-seed-demo.sh."
