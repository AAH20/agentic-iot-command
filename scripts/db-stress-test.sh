#!/usr/bin/env bash
set -euo pipefail
DB_NAME="${A2Z_DB_NAME:-opsatlas_demo}"
[[ "$DB_NAME" =~ ^opsatlas_(demo|dev)(_[a-z0-9_]+)?$ ]] || { echo "Stress tests are restricted to demo/dev database names." >&2; exit 2; }
[[ -z "${PGSERVICE:-}${PGSERVICEFILE:-}" ]] || { echo "PGSERVICE is not accepted by the local-only stress script." >&2; exit 2; }
case "${PGHOST:-localhost}" in localhost|127.0.0.1|::1) ;; *) echo "Refusing non-loopback PGHOST." >&2; exit 2 ;; esac
case "${PGHOSTADDR:-}" in ''|127.*|::1) ;; *) echo "Refusing non-loopback PGHOSTADDR." >&2; exit 2 ;; esac
[[ "${A2Z_ALLOW_STRESS_TEST:-}" == "YES_STRESS_${DB_NAME}" ]] || { echo "Set A2Z_ALLOW_STRESS_TEST=YES_STRESS_${DB_NAME} to confirm local read load." >&2; exit 2; }
BENCH_DURATION="${A2Z_STRESS_SECONDS:-30}"
CLIENTS="${A2Z_STRESS_CLIENTS:-8}"
[[ "$BENCH_DURATION" =~ ^[0-9]+$ && "$BENCH_DURATION" -ge 5 && "$BENCH_DURATION" -le 120 ]] || { echo "A2Z_STRESS_SECONDS must be 5..120." >&2; exit 2; }
[[ "$CLIENTS" =~ ^[0-9]+$ && "$CLIENTS" -ge 1 && "$CLIENTS" -le 16 ]] || { echo "A2Z_STRESS_CLIENTS must be 1..16." >&2; exit 2; }
command -v pgbench >/dev/null || { echo "pgbench is required (PostgreSQL contrib tools)." >&2; exit 2; }
psql -X -d "$DB_NAME" -Atqc "SELECT 1 FROM opsatlas.tenants WHERE slug='opsatlas-demo'" | rg -q '^1$' || { echo "Synthetic demo tenant is missing; seed the demo database first." >&2; exit 2; }
LOG_DIR="$(mktemp -d /private/tmp/opsatlas-pgbench.XXXXXX)"
echo "Transaction latency logs: $LOG_DIR"
pgbench -n -M simple -l --log-prefix="$LOG_DIR/txn" -c "$CLIENTS" -j "$((CLIENTS < 4 ? CLIENTS : 4))" -T "$BENCH_DURATION" -P 5 -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/database/pgbench_read.sql" "$DB_NAME"
python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/summarize-pgbench.py" "$LOG_DIR"
