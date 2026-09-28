#!/usr/bin/env python3
"""Local Codex MCP bridge that sends goal operations to Ubuntu over pinned SSH."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


SUPPORTED_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_LOGIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,62}$")
_GATEWAY = re.compile(r"^/[A-Za-z0-9_./-]+$")
_TOOLS = frozenset({
    "submit_infrastructure_goal",
    "propose_infrastructure_task",
    "evaluate_infrastructure_task",
    "queue_approved_infrastructure_task",
    "queue_policy_authorized_infrastructure_task",
    "get_infrastructure_goal_status",
})
_MAX_REQUEST = 256 * 1024
_MAX_REPLY = 1024 * 1024


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class SSHGoalGatewayClient:
    def __init__(self, *, alias: str, login: str, identity_file: Path,
                 known_hosts_file: Path, remote_gateway: str,
                 ssh_executable: str = "/usr/bin/ssh", timeout_seconds: int = 90) -> None:
        if not _ALIAS.fullmatch(alias) or not _LOGIN.fullmatch(login):
            raise ValueError("SSH alias/login is outside the safe identifier contract")
        if not _GATEWAY.fullmatch(remote_gateway) or ".." in Path(remote_gateway).parts:
            raise ValueError("remote gateway must be a normalized absolute path")
        if timeout_seconds < 1 or timeout_seconds > 120:
            raise ValueError("SSH gateway timeout must be between 1 and 120 seconds")
        for path in (identity_file, known_hosts_file):
            if path.is_symlink() or not path.is_file():
                raise PermissionError("SSH identity and known-hosts must be regular non-symlink files")
        if stat.S_IMODE(identity_file.stat().st_mode) & 0o077:
            raise PermissionError("SSH private key must be owner-only (chmod 600)")
        if stat.S_IMODE(known_hosts_file.stat().st_mode) & 0o022:
            raise PermissionError("dedicated known-hosts file must not be group/other writable")
        self.alias = alias
        self.login = login
        self.identity_file = identity_file
        self.known_hosts_file = known_hosts_file
        self.remote_gateway = remote_gateway
        self.ssh_executable = ssh_executable
        self.timeout_seconds = timeout_seconds

    def invoke(self, message: dict[str, Any]) -> dict[str, Any]:
        method = message.get("method")
        if method == "tools/call":
            params = message.get("params")
            if not isinstance(params, dict) or params.get("name") not in _TOOLS:
                raise PermissionError("MCP tool is outside the explicit goal-gateway allowlist")
        request_id = message.get("id")
        wire_messages = []
        if method != "initialize":
            wire_messages.append({"jsonrpc": "2.0", "id": "a2z-proxy-initialize", "method": "initialize",
                                  "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                                             "clientInfo": {"name": "a2z-macos-goal-bridge", "version": "0.1.0"}}})
            wire_messages.append({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        wire_messages.append(message)
        payload = "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in wire_messages)
        if len(payload.encode("utf-8")) > _MAX_REQUEST:
            raise ValueError("remote goal-gateway request exceeds 256 KiB")
        command = [
            self.ssh_executable, "-F", "/dev/null", "-T",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts_file}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes",
            "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "RequestTTY=no",
            "-o", "ConnectTimeout=10",
            "-i", str(self.identity_file),
            f"{self.login}@{self.alias}",
            self.remote_gateway, "--stdio",
        ]
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        if os.environ.get("SSH_AUTH_SOCK"):
            environment["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
        try:
            result = subprocess.run(
                command, input=payload, text=True, capture_output=True,
                timeout=self.timeout_seconds, check=False, shell=False,
                close_fds=True, env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ConnectionError("remote goal gateway is unavailable") from exc
        if result.returncode != 0 or len(result.stdout.encode("utf-8")) > _MAX_REPLY:
            raise ConnectionError("remote goal gateway failed or exceeded response limit")
        try:
            responses = [json.loads(line, object_pairs_hook=_unique_object)
                         for line in result.stdout.splitlines() if line.strip()]
        except (json.JSONDecodeError, ValueError) as exc:
            raise ConnectionError("remote goal gateway returned invalid protocol data") from exc
        for response in responses:
            if isinstance(response, dict) and response.get("id") == request_id:
                return response
        raise ConnectionError("remote goal gateway omitted the matching response")


def load_client(config_path: Path) -> SSHGoalGatewayClient:
    if config_path.is_symlink() or not config_path.is_file():
        raise PermissionError("Mac-side gateway config must be a regular non-symlink file")
    if stat.S_IMODE(config_path.stat().st_mode) & 0o077:
        raise PermissionError("Mac-side gateway config must be owner-only (chmod 600)")
    if config_path.stat().st_size > 64 * 1024:
        raise ValueError("Mac-side gateway config exceeds 64 KiB")
    config = json.loads(config_path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    required = {"ssh_alias", "ssh_login", "identity_file", "known_hosts_file", "remote_gateway"}
    if not isinstance(config, dict) or set(config) != required:
        raise ValueError("Mac-side gateway config fields do not match the contract")
    return SSHGoalGatewayClient(
        alias=config["ssh_alias"], login=config["ssh_login"],
        identity_file=Path(config["identity_file"]).expanduser(),
        known_hosts_file=Path(config["known_hosts_file"]).expanduser(),
        remote_gateway=config["remote_gateway"],
    )


def dispatch(message: dict[str, Any], *, client: SSHGoalGatewayClient) -> dict[str, Any] | None:
    method = message.get("method")
    if not isinstance(method, str):
        return {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32600, "message": "invalid request"}}
    if method.startswith("notifications/"):
        return None
    if method not in {"initialize", "ping", "tools/list", "tools/call"}:
        return {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601, "message": "method not found"}}
    try:
        return client.invoke(message)
    except (ConnectionError, PermissionError, ValueError, OSError):
        return {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32000, "message": "remote goal-gateway request failed; check the pinned SSH connection and Linux gateway service"}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="owner-only Mac SSH gateway registry")
    args = parser.parse_args()
    try:
        client = load_client(args.config)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"A2Z goal-gateway MCP startup failed: {exc}", file=sys.stderr)
        return 2
    for line in sys.stdin:
        try:
            message = json.loads(line, object_pairs_hook=_unique_object)
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
            else:
                response = dispatch(message, client=client)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        except Exception:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": "internal MCP error"}}
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
