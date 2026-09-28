#!/usr/bin/env bash
set -euo pipefail
DB_NAME="${A2Z_DB_NAME:-opsatlas_demo}"
[[ "$DB_NAME" =~ ^opsatlas_(demo|dev)(_[a-z0-9_]+)?$ ]] || { echo "Refusing reset: only opsatlas_demo/opsatlas_dev databases are eligible." >&2; exit 2; }
[[ -z "${PGSERVICE:-}${PGSERVICEFILE:-}" ]] || { echo "PGSERVICE is not accepted by the local-only reset script." >&2; exit 2; }
case "${PGHOST:-localhost}" in localhost|127.0.0.1|::1) ;; *) echo "Refusing non-loopback PGHOST." >&2; exit 2 ;; esac
case "${PGHOSTADDR:-}" in ''|127.*|::1) ;; *) echo "Refusing non-loopback PGHOSTADDR." >&2; exit 2 ;; esac
[[ "${A2Z_ALLOW_DEMO_RESET:-}" == "RESET_${DB_NAME}" ]] || { echo "Set A2Z_ALLOW_DEMO_RESET=RESET_${DB_NAME} to remove only the opsatlas-demo synthetic tenant." >&2; exit 2; }
psql -X -v ON_ERROR_STOP=1 -d "$DB_NAME" -c "DELETE FROM opsatlas.tenants WHERE slug='opsatlas-demo';"
echo "Synthetic tenant removed from '$DB_NAME'; schema and all other tenants were preserved."
