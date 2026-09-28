from __future__ import annotations

import json
import os
import re
import selectors
import stat
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .connectors import ConnectorManifest
from .inventory import InventoryObservation


_SAFE_HOST_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_SAFE_LOGIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,62}$")
_SAFE_HOST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_READ_ONLY_OPERATIONS = frozenset({"host.summary", "systemd.health", "virtualbox.inventory"})
_ALLOWED_ENVIRONMENTS = frozenset({"lab", "development", "staging"})
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_STDERR_BYTES = 64 * 1024
_IO_CHUNK_BYTES = 16 * 1024
_MAX_OBSERVATIONS = 1002  # 500 guests plus host summaries
_VBOX_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class SSHHost:
    """Operator-managed SSH target. `host_id` is an inventory ID, not a hostname."""

    host_id: str
    alias: str
    login: str
    tenant_id: str
    environments: tuple[str, ...]
    identity_file: Path
    known_hosts_file: Path
    helper_path: str = "/usr/local/libexec/a2z-readonly-probe"


class SSHReadOnlyConnector:
    """Live SSH observation via a pinned host and a fixed, read-only remote helper.

    This connector deliberately has no arbitrary-command API and never accepts a
    command, hostname, username, key path, or helper path from an agent request.
    The remote helper must itself enforce the operation allowlist.
    """

    def __init__(self, hosts: tuple[SSHHost, ...], *, ssh_executable: str = "/usr/bin/ssh", timeout_seconds: int = 15) -> None:
        if not hosts:
            raise ValueError("at least one explicitly configured SSH host is required")
        if timeout_seconds < 1 or timeout_seconds > 60:
            raise ValueError("SSH timeout must be between 1 and 60 seconds")
        _require_trusted_executable(Path(ssh_executable))
        self._hosts: dict[str, SSHHost] = {}
        for host in hosts:
            if (not isinstance(host.host_id, str) or not _SAFE_HOST_ID.fullmatch(host.host_id)
                    or not isinstance(host.tenant_id, str) or not host.tenant_id.strip()):
                raise ValueError("SSH host_id and tenant_id must be bounded non-empty identifiers")
            if (not isinstance(host.alias, str) or not _SAFE_HOST_ALIAS.fullmatch(host.alias)
                    or not isinstance(host.login, str) or not _SAFE_LOGIN.fullmatch(host.login)):
                raise ValueError("SSH alias or login contains unsupported characters")
            if (not host.environments
                    or any(not isinstance(environment, str) or environment not in _ALLOWED_ENVIRONMENTS
                           for environment in host.environments)
                    or len(set(host.environments)) != len(host.environments)):
                raise ValueError("SSH host environments must be unique lab, development, or staging labels")
            if host.host_id in self._hosts:
                raise ValueError("duplicate SSH inventory host ID")
            _require_private_ssh_key(host.identity_file)
            _require_trusted_known_hosts(host.known_hosts_file)
            if not re.fullmatch(r"/[A-Za-z0-9_./-]+", host.helper_path) or ".." in Path(host.helper_path).parts:
                raise ValueError("remote helper path must be a normalized absolute path")
            self._hosts[host.host_id] = host
        self._ssh_executable = ssh_executable
        self._timeout_seconds = timeout_seconds

    @property
    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            connector_id="ssh-readonly",
            domain="linux-host",
            version="0.1.0",
            capabilities=tuple(f"observe:{operation}" for operation in sorted(_READ_ONLY_OPERATIONS)),
            network_destinations=tuple(sorted({host.alias for host in self._hosts.values()})),
            credential_requirements=("operator-managed-dedicated-ssh-key", "pinned-known-hosts"),
            read_only_by_default=True,
        )

    def observe(self, *, tenant_id: str, target: str, environment: str) -> tuple[InventoryObservation, ...]:
        host = self._hosts.get(target)
        if host is None:
            raise PermissionError("SSH target is not in the operator-managed host registry")
        if host.tenant_id != tenant_id or environment not in host.environments:
            raise PermissionError("SSH target is outside the configured tenant/environment scope")

        request = json.dumps({"version": 1, "operations": sorted(_READ_ONLY_OPERATIONS)}, separators=(",", ":"))
        command = [
            self._ssh_executable,
            "-F", "/dev/null",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={host.known_hosts_file}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes",
            "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "RequestTTY=no",
            "-o", f"ConnectTimeout={min(self._timeout_seconds, 30)}",
            "-i", str(host.identity_file),
            f"{host.login}@{host.alias}",
            host.helper_path,
            "--stdio",
        ]
        try:
            process_env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
            # Allow local signing by the operator's agent for an encrypted
            # dedicated key; agent forwarding to Linux remains disabled.
            if os.environ.get("SSH_AUTH_SOCK"):
                process_env["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
            returncode, stdout = _run_bounded_process(
                command, request.encode("utf-8"), timeout_seconds=self._timeout_seconds,
                stdout_limit=_MAX_RESPONSE_BYTES, stderr_limit=_MAX_STDERR_BYTES,
                environment=process_env,
            )
        except TimeoutError as exc:
            raise TimeoutError("SSH observation timed out") from exc
        if returncode != 0:
            raise ConnectionError("SSH observation failed; inspect protected operator-side diagnostics")
        try:
            response: Any = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("SSH helper returned invalid JSON") from exc
        if not isinstance(response, dict) or response.get("version") != 1 or not isinstance(response.get("observations"), list):
            raise ValueError("SSH helper response does not match protocol version 1")

        if len(response["observations"]) > _MAX_OBSERVATIONS:
            raise ValueError("SSH helper returned too many observations")
        observations: list[InventoryObservation] = []
        seen_resource_ids: set[str] = set()
        for item in response["observations"]:
            if not isinstance(item, dict) or item.get("operation") not in _READ_ONLY_OPERATIONS:
                raise ValueError("SSH helper returned an unapproved operation")
            resource_type = item.get("resource_type")
            attributes = item.get("attributes")
            resource_id = item.get("resource_id")
            if resource_id is None:
                resource_id = {
                    "host.summary": host.host_id,
                    "systemd.health": f"{host.host_id}:systemd",
                    "virtualbox.inventory": f"{host.host_id}:virtualbox",
                }[item["operation"]]
            if (not isinstance(resource_type, str) or not isinstance(attributes, dict)
                    or not isinstance(resource_id, str) or not resource_id or len(resource_id) > 128
                    or any(ord(char) < 32 for char in resource_id)):
                raise ValueError("SSH helper returned a malformed observation")
            _validate_observation(item["operation"], resource_type, resource_id, attributes)
            if resource_id in seen_resource_ids:
                raise ValueError("SSH helper returned a duplicate resource ID")
            seen_resource_ids.add(resource_id)
            observations.append(InventoryObservation(
                observation_id=uuid4(),
                tenant_id=tenant_id,
                resource_id=resource_id,
                resource_type=resource_type,
                environment=environment,
                source_connector=self.manifest.connector_id,
                observed_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                read_only=True,
                attributes=attributes,
            ))
        return tuple(observations)


def _validate_observation(operation: str, resource_type: str, resource_id: str,
                          attributes: dict[str, Any]) -> None:
    """Enforce a privacy-minimized typed contract before evidence persistence."""
    contracts: dict[str, tuple[str, frozenset[str]]] = {
        "host.summary": ("linux-host", frozenset({"hostname", "kernel", "architecture", "distribution", "uid"})),
        "systemd.health": ("systemd-health", frozenset({"systemd_available", "failed_unit_count"})),
        "virtualbox.inventory": ("virtualbox-host", frozenset({"virtualbox_available", "registered_vm_count", "running_vm_count"})),
    }
    if operation == "virtualbox.inventory" and resource_type == "virtualbox-vm":
        allowed = {"name", "uuid", "power_state"}
        guest_uuid = attributes.get("uuid")
        if (set(attributes) != allowed or not isinstance(guest_uuid, str)
                or not _VBOX_UUID.fullmatch(guest_uuid)
                or resource_id != f"virtualbox:{guest_uuid}"
                or not isinstance(attributes.get("name"), str) or not attributes["name"]
                or len(attributes["name"]) > 256
                or attributes.get("power_state") not in {"running", "powered_off_or_not_running"}):
            raise ValueError("SSH helper returned a malformed VirtualBox VM observation")
        return
    contract = contracts.get(operation)
    if contract is None or resource_type != contract[0] or set(attributes) != contract[1]:
        raise ValueError("SSH helper observation does not match its approved typed schema")
    if operation == "host.summary":
        if (resource_id == "" or any(not isinstance(attributes.get(key), str)
                or not attributes[key] or len(attributes[key]) > 256
                for key in ("hostname", "kernel", "architecture", "distribution"))
                or type(attributes.get("uid")) is not int or attributes["uid"] < 0):
            raise ValueError("SSH helper returned malformed host summary attributes")
    elif operation == "systemd.health":
        if (type(attributes.get("systemd_available")) is not bool
                or type(attributes.get("failed_unit_count")) is not int
                or not 0 <= attributes["failed_unit_count"] <= 1000):
            raise ValueError("SSH helper returned malformed systemd health attributes")
    else:
        if (type(attributes.get("virtualbox_available")) is not bool
                or type(attributes.get("registered_vm_count")) is not int
                or type(attributes.get("running_vm_count")) is not int
                or not 0 <= attributes["running_vm_count"] <= attributes["registered_vm_count"] <= 500):
            raise ValueError("SSH helper returned malformed VirtualBox host attributes")


def _run_bounded_process(command: list[str], input_bytes: bytes, *, timeout_seconds: int,
                         stdout_limit: int, stderr_limit: int,
                         environment: dict[str, str]) -> tuple[int, bytes]:
    """Run a fixed argv process while bounding both output pipes in real time."""
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        shell=False, close_fds=True, env=environment,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stdout_pipe, stderr_pipe = process.stdout, process.stderr
    stderr_bytes = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        try:
            process.stdin.write(input_bytes)
            process.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass
        for pipe, label in ((stdout_pipe, "stdout"), (stderr_pipe, "stderr")):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, data=label)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded subprocess timed out")
            for key, _ in selector.select(min(remaining, 0.25)):
                try:
                    chunk = os.read(key.fileobj.fileno(), _IO_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.data == "stdout":
                    if len(stdout) + len(chunk) > stdout_limit:
                        raise ValueError("SSH observation response exceeds the configured size limit")
                    stdout.extend(chunk)
                else:
                    stderr_bytes += len(chunk)
                    if stderr_bytes > stderr_limit:
                        raise ValueError("SSH observation diagnostics exceed the configured size limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bounded subprocess timed out")
        return process.wait(timeout=remaining), bytes(stdout)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("bounded subprocess timed out") from exc
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        for pipe in (process.stdin, stdout_pipe, stderr_pipe):
            if not pipe.closed:
                pipe.close()


def _require_trusted_executable(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise PermissionError("SSH executable must be a trusted regular executable")
    info = path.stat()
    if os.name == "posix" and info.st_uid != 0:
        raise PermissionError("SSH executable must be root-owned")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise PermissionError("SSH executable must not be group/other writable")


def _require_private_ssh_key(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("SSH identity must be a regular non-symlink file")
    info = path.stat()
    if info.st_uid != os.geteuid():
        raise PermissionError("SSH identity must be owned by the current operator")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError("SSH identity must not be accessible to group or other users")
    _require_trusted_parent(path.parent)


def _require_trusted_known_hosts(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("pinned known-hosts file must be a regular non-symlink file")
    info = path.stat()
    if os.name == "posix" and info.st_uid not in {0, os.geteuid()}:
        raise PermissionError("pinned known-hosts file must be root- or operator-owned")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise PermissionError("pinned known-hosts file must not be group/other writable")
    _require_trusted_parent(path.parent)


def _require_trusted_parent(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise PermissionError("SSH trust-file parent must be a real directory")
    info = path.stat()
    if os.name == "posix" and info.st_uid not in {0, os.geteuid()}:
        raise PermissionError("SSH trust-file parent must be root- or operator-owned")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise PermissionError("SSH trust-file parent must not be group/other writable")
