#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_NAME="${A2Z_DB_NAME:-opsatlas_demo}"
[[ "$DB_NAME" =~ ^opsatlas_(demo|dev)(_[a-z0-9_]+)?$ ]] || { echo "Synthetic seeds are restricted to opsatlas_demo/opsatlas_dev databases." >&2; exit 2; }
[[ -z "${PGSERVICE:-}${PGSERVICEFILE:-}" ]] || { echo "PGSERVICE is not accepted by the local-only seed script." >&2; exit 2; }
case "${PGHOST:-localhost}" in localhost|127.0.0.1|::1) ;; *) echo "Refusing non-loopback PGHOST." >&2; exit 2 ;; esac
case "${PGHOSTADDR:-}" in ''|127.*|::1) ;; *) echo "Refusing non-loopback PGHOSTADDR." >&2; exit 2 ;; esac
[[ "${A2Z_ALLOW_SYNTHETIC_DATA:-}" == "YES_SYNTHETIC_${DB_NAME}" ]] || { echo "Set A2Z_ALLOW_SYNTHETIC_DATA=YES_SYNTHETIC_${DB_NAME} to confirm this demo-only operation." >&2; exit 2; }
psql -X -v ON_ERROR_STOP=1 -d "$DB_NAME" -f "$ROOT/database/demo_seed.sql"
echo "Deterministic synthetic data loaded into '$DB_NAME'; it is marked synthetic and is not live telemetry."
