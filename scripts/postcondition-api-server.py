#!/usr/bin/env python3
"""Journal-side verifier-only mTLS API; contains no runner or execution routes."""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT / "src"))

from control_plane_core.postcondition_server import (  # noqa: E402
    build_postcondition_api_service,
    validate_postcondition_api_configuration,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config", default="/etc/a2z-control-plane/postcondition-api.json",
        help="root-managed postcondition API configuration file",
    )
    parser.add_argument(
        "--check-config", action="store_true",
        help="validate trust/configuration without opening the journal or binding a socket",
    )
    args = parser.parse_args()
    if args.check_config:
        validate_postcondition_api_configuration(args.config)
        print("ALLOW: postcondition API configuration and trust files are valid; no listener started")
        return 0
    server, store = build_postcondition_api_service(args.config)
    stop_requested = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stop_requested.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    failures: list[BaseException] = []

    def serve() -> None:
        try:
            server.serve_forever(poll_interval=0.5)
        except BaseException as exc:
            failures.append(exc)

    thread = threading.Thread(target=serve, name="a2z-postcondition-api", daemon=False)
    thread.start()
    try:
        while thread.is_alive() and not stop_requested.wait(0.25):
            pass
    finally:
        server.shutdown()
        thread.join(timeout=10)
        server.server_close()
        store.close()
    if thread.is_alive():
        raise RuntimeError("postcondition API server did not stop cleanly")
    if failures:
        raise RuntimeError("postcondition API server failed") from failures[0]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
