#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import socket
import sys
from pathlib import Path

from control_plane_core.grant_signer_service import load_signing_service, serve_signing_connection


def main() -> int:
    parser = argparse.ArgumentParser(description="A2Z local, exact-scope Ed25519 grant signer")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        policy, signer, socket_path = load_signing_service(args.config)
        if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
            raise PermissionError("exactly one systemd-activated socket is required")
        listener = socket.socket(fileno=3)
        if (listener.family != socket.AF_UNIX or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or listener.getsockname() != socket_path):
            raise PermissionError("systemd socket does not match the configured local signer endpoint")
        while True:
            connection, _address = listener.accept()
            with connection:
                connection.settimeout(5)
                serve_signing_connection(connection, api_uid=policy.api_uid, policy=policy, signer=signer)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"grant signer refused to start: {type(exc).__name__}", file=sys.stderr)
        return 1
    finally:
        try:
            listener.close()
        except (NameError, OSError):
            pass


if __name__ == "__main__":
    raise SystemExit(main())
