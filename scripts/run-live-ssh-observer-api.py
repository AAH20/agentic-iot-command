#!/usr/bin/env python3
"""Start the loopback API with explicitly configured read-only SSH targets."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from control_plane_core.api import LocalControlPlaneApi, serve  # noqa: E402
from control_plane_core.ssh_connector import SSHHost, SSHReadOnlyConnector  # noqa: E402


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--config", required=True, type=Path, help="private operator-managed JSON host registry")
parser.add_argument("--host", default="127.0.0.1", help="loopback only")
parser.add_argument("--port", default=8787, type=int)
args = parser.parse_args()

if os.name == "posix":
    mode = stat.S_IMODE(args.config.stat().st_mode)
    if mode & 0o077:
        parser.error("SSH registry must not be accessible by group/other users (chmod 600)")

with args.config.open(encoding="utf-8") as stream:
    config = json.load(stream)
if not isinstance(config, dict) or not isinstance(config.get("tenant_id"), str) or not isinstance(config.get("tenant_name"), str):
    parser.error("config must define tenant_id and tenant_name")
raw_hosts = config.get("hosts")
if not isinstance(raw_hosts, list) or not raw_hosts:
    parser.error("config must contain a non-empty hosts array")
if any(not isinstance(item, dict) or not isinstance(item.get("environments"), list) or len(item["environments"]) != 1 for item in raw_hosts):
    parser.error("each host must define exactly one environment label")

try:
    hosts = tuple(SSHHost(
        host_id=item["host_id"],
        alias=item["alias"],
        login=item["login"],
        tenant_id=config["tenant_id"],
        environments=tuple(item["environments"]),
        identity_file=Path(item["identity_file"]).expanduser(),
        known_hosts_file=Path(item["known_hosts_file"]).expanduser(),
        helper_path=item.get("helper_path", "/usr/local/libexec/a2z-readonly-probe"),
    ) for item in raw_hosts)
    connector = SSHReadOnlyConnector(hosts)
except (KeyError, TypeError, ValueError) as exc:
    parser.error(f"invalid SSH host configuration: {exc}")

api = LocalControlPlaneApi()
api.store.create_tenant(config["tenant_id"], config["tenant_name"])
for host in hosts:
    api.store.register_asset(host.host_id, host.tenant_id, "linux-host", host.environments[0])
api.register_connector(connector)
serve(host=args.host, port=args.port, api=api)
