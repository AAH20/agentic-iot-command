#!/usr/bin/env python3
import argparse

from control_plane_core.api import serve


parser = argparse.ArgumentParser(description="Run the loopback-only local control-plane API")
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=8794)
args = parser.parse_args()
serve(host=args.host, port=args.port)
