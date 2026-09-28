#!/usr/bin/env python3
"""Local Codex MCP bridge for read-only Linux/VirtualBox inventory."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from uuid import UUID
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT / "src"))

from control_plane_core.evidence import EvidenceLedger  # noqa: E402
from control_plane_core.ssh_connector import SSHHost, SSHReadOnlyConnector  # noqa: E402


SUPPORTED_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
INSTRUCTIONS = (
    "This MCP server is read-only. It can observe only explicitly registered Linux hosts and their "
    "VirtualBox inventory, and verify its local evidence chain. It cannot run shell commands, "
    "change VM state, access guests, or reach other infrastructure. Ask the operator before "
    "using the inventory tool; never infer guest health from VM power state."
)


def load_settings(config_path: Path) -> tuple[str, SSHReadOnlyConnector, EvidenceLedger, dict[str, str], dict[str, dict[str, list[str]]]]:
    if config_path.is_symlink() or not config_path.is_file():
        raise PermissionError("SSH registry must be a regular non-symlink file")
    if os.name == "posix":
        info = config_path.stat()
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid != os.geteuid():
            raise PermissionError("SSH registry must be owned by the current operator")
        if mode & 0o077:
            raise PermissionError("SSH registry must be owner-only (chmod 600)")
        parent = config_path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise PermissionError("SSH registry parent must be a protected real directory")
        parent_info = parent.stat()
        if parent_info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise PermissionError("SSH registry parent must be root/operator-owned and not group/other writable")
    try:
        with config_path.open(encoding="utf-8") as stream:
            config: Any = json.load(stream, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("SSH registry must be valid duplicate-free UTF-8 JSON") from exc
    if not isinstance(config, dict) or not isinstance(config.get("tenant_id"), str) or not config["tenant_id"].strip():
        raise ValueError("config must define a non-empty tenant_id")
    raw_hosts = config.get("hosts")
    if not isinstance(raw_hosts, list) or not raw_hosts:
        raise ValueError("config must contain a non-empty hosts array")
    if any(not isinstance(item, dict) or not isinstance(item.get("environments"), list) or len(item["environments"]) != 1 for item in raw_hosts):
        raise ValueError("each host must define exactly one environment label")

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
    env_by_target = {host.host_id: host.environments[0] for host in hosts}
    if len(env_by_target) != len(hosts):
        raise ValueError("host IDs must be unique")
    baselines = _validate_baselines(config.get("virtualbox_baselines", {}), set(env_by_target))
    ledger_path = config.get("evidence_ledger")
    ledger = EvidenceLedger(Path(ledger_path).expanduser() if ledger_path else None)
    return config["tenant_id"], SSHReadOnlyConnector(hosts), ledger, env_by_target, baselines


def _validate_baselines(raw: Any, host_ids: set[str]) -> dict[str, dict[str, list[str]]]:
    if not isinstance(raw, dict) or not set(raw).issubset(host_ids):
        raise ValueError("virtualbox_baselines must map configured host IDs to baseline objects")
    result: dict[str, dict[str, list[str]]] = {}
    for host_id, baseline in raw.items():
        if not isinstance(baseline, dict) or set(baseline) != {"registered_vm_uuids", "running_vm_uuids"}:
            raise ValueError("each VirtualBox baseline must define registered_vm_uuids and running_vm_uuids")
        normalized: dict[str, list[str]] = {}
        for field in ("registered_vm_uuids", "running_vm_uuids"):
            values = baseline[field]
            if not isinstance(values, list) or len(values) > 500:
                raise ValueError("baseline UUID fields must be arrays of at most 500 UUIDs")
            try:
                canonical = [str(UUID(value)) for value in values if isinstance(value, str)]
            except (ValueError, AttributeError) as exc:
                raise ValueError("baseline contains an invalid VM UUID") from exc
            if len(canonical) != len(values) or len(set(canonical)) != len(canonical):
                raise ValueError("baseline UUIDs must be unique canonical UUID strings")
            normalized[field] = sorted(canonical)
        if not set(normalized["running_vm_uuids"]).issubset(normalized["registered_vm_uuids"]):
            raise ValueError("running baseline VMs must be registered VMs")
        result[host_id] = normalized
    return result


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate SSH registry field: {key}")
        result[key] = value
    return result


def jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def tool_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}]}


def dispatch(message: dict[str, Any], *, tenant_id: str, connector: SSHReadOnlyConnector,
             ledger: EvidenceLedger, env_by_target: dict[str, str],
             baselines: dict[str, dict[str, list[str]]] | None = None) -> dict[str, Any] | None:
    baselines = baselines or {}
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params", {})
    if not isinstance(method, str):
        return jsonrpc_error(request_id, -32600, "invalid request") if "id" in message else None
    if method.startswith("notifications/"):
        return None
    if method == "initialize":
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        protocol = requested if requested in SUPPORTED_PROTOCOLS else "2025-03-26"
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": protocol,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "a2z-virtualbox-observer", "version": "0.1.0"},
            "instructions": INSTRUCTIONS,
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        tools = [
            {
                "name": "observe_virtualbox_host",
                "description": "Read-only: observe one preconfigured Linux host and its VirtualBox registered/running VM inventory over pinned SSH. Makes no changes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"host_id": {"type": "string", "enum": sorted(env_by_target)}},
                    "required": ["host_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "verify_inventory_evidence",
                "description": "Read-only: verify the local tenant evidence chain; this does not verify a VM's guest health.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        ]
        if baselines:
            tools.append({
                "name": "compare_virtualbox_to_baseline",
                "description": "Read-only: take a fresh inventory of a host with an operator-configured baseline, report exact VM registration/power-state drift, and append evidence. Never changes or replaces the baseline.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"host_id": {"type": "string", "enum": sorted(baselines)}},
                    "required": ["host_id"],
                    "additionalProperties": False,
                },
            })
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}}
    if method != "tools/call":
        return jsonrpc_error(request_id, -32601, "method not found")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str) or not isinstance(params.get("arguments", {}), dict):
        return jsonrpc_error(request_id, -32602, "invalid tool call")

    name = params["name"]
    arguments = params.get("arguments", {})
    try:
        if name == "observe_virtualbox_host":
            if set(arguments) != {"host_id"} or arguments["host_id"] not in env_by_target:
                raise ValueError("host_id must be one of the configured hosts")
            target = arguments["host_id"]
            observations = connector.observe(tenant_id=tenant_id, target=target, environment=env_by_target[target])
            serialized = [observation.as_dict() for observation in observations]
            record = ledger.record(
                tenant_id=tenant_id,
                event_type="inventory.observed",
                collector="a2z-virtualbox-observer/0.1.0",
                payload={"tenant_id": tenant_id, "target": target, "observations": serialized},
            )
            return {"jsonrpc": "2.0", "id": request_id, "result": tool_result({
                "tenant_id": tenant_id,
                "target": target,
                "observations": serialized,
                "evidence": {"sequence": record.sequence, "record_sha256": record.record_sha256},
                "changed_infrastructure": False,
            })}
        if name == "verify_inventory_evidence":
            if arguments:
                raise ValueError("this tool takes no arguments")
            return {"jsonrpc": "2.0", "id": request_id, "result": tool_result(ledger.verify(tenant_id=tenant_id))}
        if name == "compare_virtualbox_to_baseline":
            if set(arguments) != {"host_id"} or arguments["host_id"] not in baselines:
                raise ValueError("host_id must have an operator-configured VirtualBox baseline")
            target = arguments["host_id"]
            observations = connector.observe(tenant_id=tenant_id, target=target, environment=env_by_target[target])
            hosts = [item for item in observations if item.resource_type == "virtualbox-host"]
            if len(hosts) != 1 or hosts[0].attributes.get("virtualbox_available") is not True:
                raise ValueError("fresh inventory did not confirm exactly one available VirtualBox host")
            observed_vms = [item for item in observations if item.resource_type == "virtualbox-vm"]
            observed_uuids: list[str] = []
            running_uuids: list[str] = []
            for item in observed_vms:
                try:
                    guest_uuid = str(UUID(item.attributes["uuid"]))
                except (KeyError, ValueError, AttributeError, TypeError) as exc:
                    raise ValueError("fresh VM inventory contains a malformed UUID") from exc
                if guest_uuid in observed_uuids:
                    raise ValueError("fresh VM inventory contains duplicate UUIDs")
                observed_uuids.append(guest_uuid)
                if item.attributes.get("power_state") == "running":
                    running_uuids.append(guest_uuid)
            if len(observed_uuids) > 500:
                raise ValueError("fresh VirtualBox inventory exceeds the supported VM limit")
            expected = baselines[target]
            registered_missing = sorted(set(expected["registered_vm_uuids"]) - set(observed_uuids))
            registered_unexpected = sorted(set(observed_uuids) - set(expected["registered_vm_uuids"]))
            running_missing = sorted(set(expected["running_vm_uuids"]) - set(running_uuids))
            running_unexpected = sorted(set(running_uuids) - set(expected["running_vm_uuids"]))
            drift = {
                "registered_missing": registered_missing,
                "registered_unexpected": registered_unexpected,
                "running_missing": running_missing,
                "running_unexpected": running_unexpected,
            }
            record = ledger.record(
                tenant_id=tenant_id,
                event_type="inventory.baseline_comparison",
                collector="a2z-virtualbox-observer/0.1.0",
                payload={"tenant_id": tenant_id, "target": target, "baseline": expected,
                         "observed_registered_vm_uuids": sorted(observed_uuids),
                         "observed_running_vm_uuids": sorted(running_uuids), "drift": drift},
            )
            return {"jsonrpc": "2.0", "id": request_id, "result": tool_result({
                "tenant_id": tenant_id, "target": target,
                "baseline_match": not any(drift.values()), "drift": drift,
                "evidence": {"sequence": record.sequence, "record_sha256": record.record_sha256},
                "changed_infrastructure": False, "baseline_changed": False,
            })}
        raise ValueError("unknown tool")
    except (ValueError, PermissionError, ConnectionError, TimeoutError, OSError) as exc:
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            **tool_result({"error": str(exc)}), "isError": True,
        }}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="private operator-managed SSH registry JSON")
    args = parser.parse_args()
    try:
        tenant_id, connector, ledger, env_by_target, baselines = load_settings(args.config)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"A2Z MCP startup failed: {exc}", file=sys.stderr)
        return 2

    for line in sys.stdin:
        try:
            message = json.loads(line)
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                response = jsonrpc_error(message.get("id") if isinstance(message, dict) else None, -32600, "invalid request")
            else:
                response = dispatch(message, tenant_id=tenant_id, connector=connector, ledger=ledger,
                                    env_by_target=env_by_target, baselines=baselines)
        except (json.JSONDecodeError, UnicodeDecodeError):
            response = jsonrpc_error(None, -32700, "parse error")
        except Exception:
            response = jsonrpc_error(message.get("id") if isinstance(message, dict) else None, -32603, "internal MCP error")
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
