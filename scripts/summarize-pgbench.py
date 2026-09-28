#!/usr/bin/env python3
"""Summarize PostgreSQL pgbench per-transaction latency logs (microseconds)."""
from __future__ import annotations

import pathlib
import sys


def percentile(sorted_values: list[int], pct: float) -> int:
    return sorted_values[max(0, (len(sorted_values) * int(pct * 100) + 99) // 100 - 1)]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize-pgbench.py LOG_DIRECTORY", file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1]).resolve()
    if not root.is_dir() or not root.name.startswith("opsatlas-pgbench."):
        print("refusing unexpected log directory", file=sys.stderr)
        return 2
    values: list[int] = []
    for path in sorted(root.glob("txn.*")):
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            try:
                # pgbench log format starts: client_id txn_no latency_us script_no ...
                values.append(int(fields[2]))
            except ValueError:
                continue
    if not values:
        print("No transaction samples found.", file=sys.stderr)
        return 1
    values.sort()
    print(f"transactions={len(values)} p50_ms={percentile(values,.50)/1000:.3f} p95_ms={percentile(values,.95)/1000:.3f} p99_ms={percentile(values,.99)/1000:.3f} max_ms={values[-1]/1000:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
