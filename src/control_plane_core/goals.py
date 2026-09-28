from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from .autonomy import AutonomyDisposition, AutonomyPolicyEngine, AutonomyRequest
from .autonomy_catalog import TRUSTED_OPERATION_CONTRACTS, validate_operation_plan
from .autonomy_profiles import AutonomyProfileVerifier, load_signed_autonomy_profile_record
from .impact_assessments import impact_assessment_digest as _impact_assessment_digest


MAX_GOAL_BYTES = 64 * 1024
TASK_STATES = frozenset({
    "pending_policy", "auto_eligible", "approval_required", "denied",
    "queued", "leased", "running", "verification", "completed",
    "failed", "cancelled", "blocked",
})
_TRANSITIONS = {
    "pending_policy": {"auto_eligible", "approval_required", "denied", "blocked", "cancelled"},
    "auto_eligible": {"approval_required", "denied", "queued", "blocked", "cancelled"},
    "approval_required": {"queued", "denied", "blocked", "cancelled"},
    "queued": {"leased", "cancelled", "blocked"},
    "leased": {"queued", "running", "cancelled", "blocked"},
    "running": {"verification", "failed", "blocked"},
    "verification": {"completed", "failed", "blocked"},
    "blocked": {"pending_policy", "approval_required", "cancelled"},
    "denied": set(), "completed": set(), "failed": set(), "cancelled": set(),
}
_NON_EXECUTABLE_STATES = frozenset({"auto_eligible", "approval_required", "queued", "leased", "running", "verification"})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate plan JSON key: {key}")
        value[key] = item
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class GoalReceipt:
    goal_id: str
    tenant_id: str
    status: str
    created: bool

    def as_dict(self) -> dict[str, Any]:
        return {"goal_id": self.goal_id, "tenant_id": self.tenant_id, "status": self.status, "created": self.created}


class DurableGoalStore:
    """Local SQLite journal for typed, governed goals; it is not an executor.

    Goals are operator-submitted outcomes. Codex/planners must convert them into
    typed, target-scoped tasks; free text is never interpreted as a shell command.
    The store records policy decisions and workflow transitions. Queueing,
    lease start, and permit consumption require injected verifiers; none of
    these transitions invokes an infrastructure adapter.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().absolute()
        if not self.path.parent.is_dir():
            raise ValueError("goal database parent directory must already exist")
        if self.path.is_symlink():
            raise PermissionError("goal database may not be a symlink")
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
        os.chmod(self.path, 0o600)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA journal_mode=DELETE")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS goals (
                goal_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                objective TEXT NOT NULL,
                guardrails_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (tenant_id, requested_by, idempotency_key)
            );
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                goal_id TEXT NOT NULL REFERENCES goals(goal_id),
                tenant_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                target_ids_json TEXT NOT NULL,
                environment TEXT NOT NULL,
                plan_json TEXT NOT NULL DEFAULT '{}',
                plan_digest TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                approval_ref TEXT,
                lease_owner TEXT,
                lease_until TEXT,
                lease_token TEXT,
                lease_stage TEXT,
                lease_generation INTEGER NOT NULL DEFAULT 0,
                execution_deadline TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS goal_events (
                event_no INTEGER PRIMARY KEY AUTOINCREMENT,
                sequence INTEGER NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                goal_id TEXT NOT NULL REFERENCES goals(goal_id),
                task_id TEXT,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (tenant_id, goal_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS tasks_queue_idx ON tasks(status, created_at);
            CREATE INDEX IF NOT EXISTS events_goal_idx ON goal_events(tenant_id, goal_id, sequence);
            CREATE TABLE IF NOT EXISTS consumed_approvals (
                approval_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                consumed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runner_attestations (
                receipt_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                tenant_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                lease_generation INTEGER NOT NULL,
                envelope_json TEXT NOT NULL,
                attestation_sha256 TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE (task_id, lease_generation, target_id)
            );
            CREATE TABLE IF NOT EXISTS postcondition_attestations (
                verification_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                tenant_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                lease_generation INTEGER NOT NULL,
                envelope_json TEXT NOT NULL,
                attestation_sha256 TEXT NOT NULL,
                expected_state_sha256 TEXT NOT NULL,
                observed_state_sha256 TEXT NOT NULL,
                verified INTEGER NOT NULL CHECK (verified IN (0,1)),
                recorded_at TEXT NOT NULL,
                UNIQUE (task_id,lease_generation)
            );
            CREATE TABLE IF NOT EXISTS execution_grants (
                grant_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                tenant_id TEXT NOT NULL,
                lease_generation INTEGER NOT NULL,
                envelope_json TEXT NOT NULL,
                grant_sha256 TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                consumed_at TEXT,
                consumed_by TEXT,
                UNIQUE (task_id, lease_generation)
            );
            CREATE TABLE IF NOT EXISTS circuit_breakers (
                tenant_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                environment TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('open','closed')),
                goal_id TEXT NOT NULL REFERENCES goals(goal_id),
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                last_receipt_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                opened_at TEXT NOT NULL,
                reset_approval_id TEXT,
                reset_evidence_sha256 TEXT,
                reset_at TEXT,
                PRIMARY KEY (tenant_id,target_id,operation_id)
            );
        """)
        task_columns = {row["name"] for row in self._db.execute("PRAGMA table_info(tasks)")}
        for column in ("lease_token", "lease_stage"):
            if column not in task_columns:
                self._db.execute(f"ALTER TABLE tasks ADD COLUMN {column} TEXT")
        if "lease_generation" not in task_columns:
            self._db.execute("ALTER TABLE tasks ADD COLUMN lease_generation INTEGER NOT NULL DEFAULT 0")
        if "execution_deadline" not in task_columns:
            self._db.execute("ALTER TABLE tasks ADD COLUMN execution_deadline TEXT")
        if "plan_json" not in task_columns:
            self._db.execute("ALTER TABLE tasks ADD COLUMN plan_json TEXT NOT NULL DEFAULT '{}'")
        grant_columns = {row["name"] for row in self._db.execute("PRAGMA table_info(execution_grants)")}
        for column in ("consumed_at", "consumed_by"):
            if column not in grant_columns:
                self._db.execute(f"ALTER TABLE execution_grants ADD COLUMN {column} TEXT")
        info = self.path.stat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            self._db.close()
            raise PermissionError("goal database must be a regular owner-only file")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def submit_goal(
        self,
        *,
        tenant_id: str,
        requested_by: str,
        idempotency_key: str,
        objective: str,
        guardrails: dict[str, Any],
    ) -> GoalReceipt:
        for label, value in (("tenant_id", tenant_id), ("requested_by", requested_by), ("idempotency_key", idempotency_key)):
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{label} must be a non-empty string of at most 256 characters")
        if not isinstance(objective, str) or not objective.strip() or len(objective.encode("utf-8")) > MAX_GOAL_BYTES:
            raise ValueError("objective must be non-empty and at most 64 KiB")
        if not isinstance(guardrails, dict) or len(_canonical(guardrails)) > MAX_GOAL_BYTES:
            raise ValueError("guardrails must be a JSON object of at most 64 KiB")
        guardrails_json = _canonical(guardrails).decode()
        with self._transaction():
            request_digest = hashlib.sha256(_canonical({"objective": objective, "guardrails": guardrails})).hexdigest()
            row = self._db.execute(
                "SELECT goal_id,status,request_digest FROM goals WHERE tenant_id=? AND requested_by=? AND idempotency_key=?",
                (tenant_id, requested_by, idempotency_key),
            ).fetchone()
            if row:
                if row["request_digest"] != request_digest:
                    raise ValueError("idempotency key was already used with a different goal payload")
                return GoalReceipt(row["goal_id"], tenant_id, row["status"], False)
            goal_id, stamp = str(uuid4()), _now()
            self._db.execute(
                "INSERT INTO goals VALUES (?,?,?,?,?,?,?,?,?)",
                (goal_id, tenant_id, requested_by, idempotency_key, request_digest, objective, guardrails_json, "submitted", stamp),
            )
            self._append_event(tenant_id, goal_id, None, "goal.submitted", {"requested_by": requested_by, "objective_sha256": hashlib.sha256(objective.encode()).hexdigest(), "guardrails": guardrails})
            return GoalReceipt(goal_id, tenant_id, "submitted", True)

    def add_task(
        self,
        *,
        goal_id: str,
        tenant_id: str,
        operation_id: str,
        target_ids: tuple[str, ...],
        environment: str,
        plan: dict[str, Any],
        policy_digest: str = "",
    ) -> dict[str, Any]:
        if (not isinstance(operation_id, str) or not operation_id.strip() or len(operation_id) > 128
                or operation_id in {"*", "shell.exec", "command.run"}):
            raise ValueError("task requires a specific registered operation; generic command execution is forbidden")
        if (not isinstance(target_ids, (tuple, list)) or not target_ids or len(target_ids) > 20
                or any(not isinstance(target, str) or not target.strip() or len(target) > 256 for target in target_ids)
                or len(set(target_ids)) != len(target_ids)):
            raise ValueError("task requires unique exact target IDs")
        if environment not in {"lab", "development", "staging", "production", "regulated"}:
            raise ValueError("environment is not recognized")
        plan_json, plan_digest = self._validate_plan(
            plan, operation_id=operation_id, target_ids=target_ids, environment=environment,
        )
        if policy_digest and (not isinstance(policy_digest, str) or len(policy_digest) != 64 or any(c not in "0123456789abcdef" for c in policy_digest)):
            raise ValueError("policy_digest must be a lowercase SHA-256 digest")
        with self._transaction():
            goal = self._db.execute("SELECT status FROM goals WHERE goal_id=? AND tenant_id=?", (goal_id, tenant_id)).fetchone()
            if not goal:
                raise KeyError("goal not found in tenant scope")
            if goal["status"] not in {"submitted", "planning"}:
                raise PermissionError("goal is not accepting planned tasks")
            task_id, stamp = str(uuid4()), _now()
            targets_json = _canonical(list(target_ids)).decode()
            self._db.execute(
                "INSERT INTO tasks (task_id,goal_id,tenant_id,operation_id,target_ids_json,environment,plan_json,plan_digest,policy_digest,status,decision_json,approval_ref,lease_owner,lease_until,lease_token,lease_stage,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (task_id, goal_id, tenant_id, operation_id, targets_json, environment, plan_json, plan_digest, policy_digest,
                 "pending_policy", "{}", None, None, None, None, None, stamp, stamp),
            )
            self._db.execute("UPDATE goals SET status='planning' WHERE goal_id=?", (goal_id,))
            self._append_event(tenant_id, goal_id, task_id, "task.created", {
                "operation_id": operation_id, "target_ids": list(target_ids), "environment": environment,
                "plan": json.loads(plan_json), "plan_sha256": plan_digest,
            })
            return self.get_task(task_id=task_id, tenant_id=tenant_id)

    @staticmethod
    def _validate_plan(plan: dict[str, Any], *, operation_id: str, target_ids: tuple[str, ...],
                       environment: str) -> tuple[str, str]:
        required = {
            "schema_version", "operation_id", "target_ids", "environment", "preconditions",
            "desired_state", "rollback", "max_runtime_seconds",
        }
        if not isinstance(plan, dict) or set(plan) != required:
            raise ValueError("plan fields must exactly match a2z-task-plan-v1")
        if plan["schema_version"] != "a2z-task-plan-v1" or plan["operation_id"] != operation_id:
            raise ValueError("plan version or operation_id does not match the task")
        if plan["target_ids"] != list(target_ids) or plan["environment"] != environment:
            raise ValueError("plan targets or environment do not exactly match the task")
        for field in ("preconditions", "desired_state", "rollback"):
            if not isinstance(plan[field], dict) or not plan[field]:
                raise ValueError(f"plan {field} must be a non-empty object")
        DurableGoalStore._validate_plan_values(plan)
        runtime = plan["max_runtime_seconds"]
        if isinstance(runtime, bool) or not isinstance(runtime, int) or not 1 <= runtime <= 1800:
            raise ValueError("plan max_runtime_seconds must be between 1 and 1800")
        try:
            canonical_plan = _canonical(plan)
        except (TypeError, ValueError) as exc:
            raise ValueError("plan must contain only JSON-compatible values") from exc
        if len(canonical_plan) > MAX_GOAL_BYTES:
            raise ValueError("plan artifact exceeds 64 KiB")
        plan_json = canonical_plan.decode("utf-8")
        return plan_json, hashlib.sha256(canonical_plan).hexdigest()

    @staticmethod
    def _validate_plan_values(value: Any) -> None:
        sensitive_keys = {
            "password", "passwd", "secret", "secrets", "credential", "credentials",
            "private_key", "privatekey", "access_token", "refresh_token", "client_secret",
            "token", "api_key", "access_key", "session_key", "key_material", "authorization",
        }
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValueError("plan object keys must be strings")
                normalized = key.lower().replace("-", "_")
                compact = normalized.replace("_", "")
                compact_sensitive = {item.replace("_", "") for item in sensitive_keys}
                if (normalized in sensitive_keys or compact in compact_sensitive
                        or normalized.endswith(("_secret", "_password", "_credential", "_private_key", "_token"))):
                    raise PermissionError("plan artifacts must not contain secret or credential fields")
                DurableGoalStore._validate_plan_values(child)
        elif isinstance(value, list):
            for child in value:
                DurableGoalStore._validate_plan_values(child)

    def claim_policy_task(self, *, task_id: str, tenant_id: str, worker_id: str, lease_seconds: int = 60) -> dict[str, Any]:
        if not worker_id.strip() or len(worker_id) > 128:
            raise ValueError("worker_id must be a non-empty bounded identifier")
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 600:
            raise ValueError("policy lease must be between 1 and 600 seconds")
        with self._transaction():
            task = self._db.execute(
                "SELECT status,lease_stage,lease_until FROM tasks WHERE task_id=? AND tenant_id=?",
                (task_id, tenant_id),
            ).fetchone()
            if not task:
                raise KeyError("task not found in tenant scope")
            if task["status"] != "pending_policy":
                raise PermissionError("only a pending-policy task can be leased for policy evaluation")
            now = datetime.now(timezone.utc)
            if task["lease_until"] and task["lease_until"] > now.isoformat(timespec="seconds").replace("+00:00", "Z"):
                raise PermissionError("task already has an active worker lease")
            expires = now.timestamp() + lease_seconds
            until = datetime.fromtimestamp(expires, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            token = str(uuid4())
            self._db.execute(
                "UPDATE tasks SET lease_owner=?,lease_until=?,lease_token=?,lease_stage='policy_evaluation',updated_at=? WHERE task_id=?",
                (worker_id, until, token, _now(), task_id),
            )
            task_goal = self._db.execute("SELECT goal_id FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            self._append_event(tenant_id, task_goal["goal_id"], task_id, "task.policy_lease_claimed", {"worker_id": worker_id, "lease_until": until})
            return self.get_task(task_id=task_id, tenant_id=tenant_id) | {"lease_token": token}

    def record_decision(self, *, task_id: str, tenant_id: str, lease_token: str, disposition: str,
                        reasons: tuple[str, ...], policy_digest: str,
                        impact_assessment_digest: str = "",
                        impact_assessment_record: dict[str, Any] | None = None,
                        autonomy_profile_record: dict[str, Any] | None = None,
                        autonomy_profile_verifier: Any | None = None) -> dict[str, Any]:
        if disposition not in {"auto_eligible", "approval_required", "denied"}:
            raise ValueError("decision must come from the governed policy decision point")
        if disposition == "auto_eligible" and (len(policy_digest) != 64 or any(c not in "0123456789abcdef" for c in policy_digest)):
            raise PermissionError("auto-eligible decisions require a signed policy digest")
        if impact_assessment_digest and (len(impact_assessment_digest) != 64 or any(c not in "0123456789abcdef" for c in impact_assessment_digest)):
            raise ValueError("impact assessment digest must be a lowercase SHA-256 digest")
        if impact_assessment_record is not None:
            if (_impact_assessment_digest(impact_assessment_record) != impact_assessment_digest
                    or len(_canonical(impact_assessment_record)) > MAX_GOAL_BYTES):
                raise ValueError("impact assessment evidence does not match its verified digest or size limit")
        elif impact_assessment_digest:
            raise ValueError("impact assessment digest requires the signed assessment evidence")
        if disposition == "auto_eligible":
            if autonomy_profile_record is None or autonomy_profile_verifier is None:
                raise PermissionError("auto-eligible decisions require the signed autonomy profile and trusted verifier")
            if (not isinstance(autonomy_profile_record, dict)
                    or set(autonomy_profile_record) != {"profile", "signature"}
                    or not isinstance(autonomy_profile_record.get("profile"), dict)):
                raise ValueError("signed autonomy profile record is malformed")
            verified_profile_digest = autonomy_profile_verifier.verify(autonomy_profile_record)
            if (verified_profile_digest != policy_digest
                    or autonomy_profile_record["profile"].get("tenant_id") != tenant_id
                    or autonomy_profile_record["profile"].get("enabled") is not True):
                raise PermissionError("signed autonomy profile does not match the tenant, enabled state, or decision digest")
        elif autonomy_profile_record is not None:
            raise ValueError("autonomy profile evidence is retained only for auto-eligible decisions")
        decision = {"disposition": disposition, "reasons": list(reasons), "policy_digest": policy_digest,
                    "impact_assessment_digest": impact_assessment_digest or None,
                    "impact_assessment": impact_assessment_record,
                    "autonomy_profile": autonomy_profile_record,
                    "execution_permitted": False}
        with self._transaction():
            task = self._db.execute("SELECT goal_id,status,lease_token,lease_stage,lease_until FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id)).fetchone()
            if not task:
                raise KeyError("task not found in tenant scope")
            if task["status"] != "pending_policy":
                raise PermissionError("policy decision can only be recorded for a pending task")
            now_text = _now()
            if task["lease_stage"] != "policy_evaluation" or task["lease_token"] != lease_token or not task["lease_until"] or task["lease_until"] <= now_text:
                raise PermissionError("a current policy-evaluation lease is required")
            self._db.execute("UPDATE tasks SET status=?,decision_json=?,policy_digest=?,lease_owner=NULL,lease_until=NULL,lease_token=NULL,lease_stage=NULL,updated_at=? WHERE task_id=?", (disposition, _canonical(decision).decode(), policy_digest, now_text, task_id))
            self._append_event(tenant_id, task["goal_id"], task_id, "task.policy_decided", decision)
            return self.get_task(task_id=task_id, tenant_id=tenant_id)

    def queue_task(self, *, task_id: str, tenant_id: str, signed_approval: dict[str, Any], approval_verifier: Any) -> dict[str, Any]:
        """Queue one non-production task only after a single-use signed approval verifies."""
        if not isinstance(signed_approval, dict) or len(_canonical(signed_approval)) > MAX_GOAL_BYTES:
            raise ValueError("signed approval must be a JSON object of at most 64 KiB")
        with self._lock:
            task = self._db.execute(
                "SELECT goal_id,tenant_id,operation_id,target_ids_json,environment,plan_json,plan_digest,status,decision_json FROM tasks WHERE task_id=? AND tenant_id=?",
                (task_id, tenant_id),
            ).fetchone()
        if not task:
            raise KeyError("task not found in tenant scope")
        if task["status"] != "approval_required" or task["environment"] in {"production", "regulated"}:
            raise PermissionError("only a non-production task awaiting operator approval can be queued")
        targets = json.loads(task["target_ids_json"])
        self._assert_stored_plan(task, targets)
        if len(targets) != 1:
            raise PermissionError("signed approval currently requires exactly one task target")
        plan_digest = task["plan_digest"]
        if not isinstance(plan_digest, str) or len(plan_digest) != 64 or any(c not in "0123456789abcdef" for c in plan_digest):
            raise PermissionError("task must have a SHA-256 plan digest before approval")
        expected_scope = {
            "tenant_id": tenant_id,
            "target": targets[0],
            "action": task["operation_id"],
            "environment": task["environment"],
            "capabilities": ["task.execute", f"plan.sha256:{plan_digest}"],
            "plan_id": task_id,
        }
        if approval_verifier is None:
            raise PermissionError("trusted signed-approval verifier is unavailable")
        approval = approval_verifier.verify(signed_approval, expected_scope=expected_scope)
        if approval.get("request_id") != task["goal_id"]:
            raise PermissionError("signed approval request_id does not match the task's goal")
        approval_id = approval["approval_id"]
        approval_digest = hashlib.sha256(_canonical(signed_approval)).hexdigest()
        decision = json.loads(task["decision_json"])
        decision["approval"] = {
            "approval_id": approval_id,
            "approver_id": approval["approver_id"],
            "signed_record_sha256": approval_digest,
            "signed_record": signed_approval,
        }
        decision["authorization_mode"] = "operator_approval"
        decision["execution_permitted"] = False
        with self._transaction():
            current = self._db.execute(
                "SELECT goal_id,operation_id,target_ids_json,environment,plan_json,plan_digest,status FROM tasks WHERE task_id=? AND tenant_id=?",
                (task_id, tenant_id),
            ).fetchone()
            if (not current or current["status"] != "approval_required" or current["goal_id"] != task["goal_id"]
                    or current["operation_id"] != task["operation_id"] or current["target_ids_json"] != task["target_ids_json"]
                    or current["environment"] != task["environment"] or current["plan_json"] != task["plan_json"]
                    or current["plan_digest"] != plan_digest):
                raise PermissionError("task changed while signed approval was being verified")
            try:
                self._db.execute(
                    "INSERT INTO consumed_approvals (approval_id,tenant_id,task_id,consumed_at) VALUES (?,?,?,?)",
                    (approval_id, tenant_id, task_id, _now()),
                )
            except sqlite3.IntegrityError as exc:
                raise PermissionError("signed approval was already consumed") from exc
            stamp = _now()
            self._db.execute(
                "UPDATE tasks SET status='queued',approval_ref=?,decision_json=?,updated_at=? WHERE task_id=? AND tenant_id=?",
                (approval_id, _canonical(decision).decode(), stamp, task_id, tenant_id),
            )
            self._append_event(tenant_id, task["goal_id"], task_id, "task.approved_and_queued", {
                "approval_id": approval_id, "approver_id": approval["approver_id"],
                "authorization_mode": "operator_approval", "authorization_id": approval_id,
                "signed_record_sha256": approval_digest, "signed_record": signed_approval,
                "execution_permitted": False,
            })
        return self.get_task(task_id=task_id, tenant_id=tenant_id)

    def queue_autonomous_task(self, *, task_id: str, tenant_id: str,
                              autonomy_profile_verifier: AutonomyProfileVerifier,
                              impact_verifier: Any) -> dict[str, Any]:
        """Queue routine work only after revalidating signed policy and estimate."""
        if autonomy_profile_verifier is None or impact_verifier is None:
            raise PermissionError("trusted autonomy-profile and impact-assessment verifiers are required")
        with self._transaction():
            task = self._db.execute(
                "SELECT t.*,g.guardrails_json FROM tasks t JOIN goals g ON g.goal_id=t.goal_id "
                "WHERE t.task_id=? AND t.tenant_id=?",
                (task_id, tenant_id),
            ).fetchone()
            if not task:
                raise KeyError("task not found in tenant scope")
            if task["status"] != "auto_eligible" or task["environment"] in {"production", "regulated"}:
                raise PermissionError("only a current auto-eligible non-production task can be queued by policy")
            active = self._db.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE tenant_id=? AND task_id<>? "
                "AND status IN ('queued','leased','running','verification')",
                (tenant_id, task_id),
            ).fetchone()["count"]
            profile, assessment = self._revalidate_autonomous_task(
                task, autonomy_profile_verifier=autonomy_profile_verifier,
                impact_verifier=impact_verifier, active_concurrency=active,
            )
            decision = json.loads(task["decision_json"])
            queued_at = _now()
            decision["authorization_mode"] = "standing_policy"
            decision["autonomous_queue"] = {
                "authorization_id": str(uuid4()),
                "queued_at": queued_at,
                "policy_digest": profile.policy_digest,
                "impact_assessment_digest": assessment.assessment_digest,
                "execution_permitted": False,
            }
            current = self._db.execute(
                "SELECT status,decision_json,plan_digest FROM tasks WHERE task_id=? AND tenant_id=?",
                (task_id, tenant_id),
            ).fetchone()
            if (not current or current["status"] != "auto_eligible"
                    or current["decision_json"] != task["decision_json"]
                    or current["plan_digest"] != task["plan_digest"]):
                raise PermissionError("autonomous task changed during policy revalidation")
            self._db.execute(
                "UPDATE tasks SET status='queued',decision_json=?,updated_at=? WHERE task_id=? AND tenant_id=?",
                (_canonical(decision).decode(), queued_at, task_id, tenant_id),
            )
            self._append_event(tenant_id, task["goal_id"], task_id, "task.autonomous_policy_queued", {
                "authorization_id": decision["autonomous_queue"]["authorization_id"],
                "policy_digest": profile.policy_digest,
                "impact_assessment_digest": assessment.assessment_digest,
                "authorization_mode": "standing_policy",
                "execution_permitted": False,
            })
        return self.get_task(task_id=task_id, tenant_id=tenant_id)

    def _revalidate_autonomous_task(self, task: Any, *, autonomy_profile_verifier: Any,
                                    impact_verifier: Any, active_concurrency: int):
        decision = json.loads(task["decision_json"])
        if decision.get("disposition") != "auto_eligible":
            raise PermissionError("stored task does not have an auto-eligible policy decision")
        profile_record = decision.get("autonomy_profile")
        profile = load_signed_autonomy_profile_record(
            profile_record, verifier=autonomy_profile_verifier,
        )
        if profile.tenant_id != task["tenant_id"] or profile.policy_digest != task["policy_digest"]:
            raise PermissionError("retained signed autonomy profile no longer matches task scope or digest")
        if not profile.enabled:
            raise PermissionError("standing autonomy profile is disabled")
        targets = json.loads(task["target_ids_json"])
        self._assert_stored_plan(task, targets)
        if len(targets) != 1:
            raise PermissionError("routine autonomy currently requires exactly one target")
        goals = self._db.execute(
            "SELECT guardrails_json FROM goals WHERE goal_id=? AND tenant_id=?",
            (task["goal_id"], task["tenant_id"]),
        ).fetchone()
        if not goals:
            raise PermissionError("task goal governance envelope is unavailable")
        guardrails = json.loads(goals["guardrails_json"])
        if (guardrails.get("autonomy_enabled") is not True
                or task["environment"] not in guardrails.get("allowed_environments", [])
                or not set(targets).issubset(set(guardrails.get("allowed_targets", [])))):
            raise PermissionError("task is outside its immutable goal governance envelope")
        assessment_record = decision.get("impact_assessment")
        if not isinstance(assessment_record, dict):
            raise PermissionError("autonomous dispatch requires the retained signed impact assessment")
        assessment = impact_verifier.verify(assessment_record, expected={
            "tenant_id": task["tenant_id"], "task_id": task["task_id"],
            "operation_id": task["operation_id"], "target_ids": tuple(targets),
            "environment": task["environment"], "plan_digest": task["plan_digest"],
        })
        if (assessment.assessment_digest != decision.get("impact_assessment_digest")
                or assessment.assessment_digest != _impact_assessment_digest(assessment_record)):
            raise PermissionError("retained impact assessment digest no longer matches task decision")
        contract = TRUSTED_OPERATION_CONTRACTS.get(task["operation_id"])
        plan = json.loads(task["plan_json"], object_pairs_hook=_unique_pairs)
        plan_reasons = validate_operation_plan(task["operation_id"], plan)
        if plan_reasons:
            raise PermissionError("task plan failed code-owned validation: " + ",".join(plan_reasons))
        reevaluated = AutonomyPolicyEngine().evaluate(
            profile,
            AutonomyRequest(
                tenant_id=task["tenant_id"], action_id=task["operation_id"],
                target_ids=tuple(targets), environment=task["environment"],
                plan_digest=task["plan_digest"], task_id=task["task_id"],
                active_concurrency=active_concurrency,
                max_runtime_seconds=plan["max_runtime_seconds"],
                impact_assessment=assessment,
            ),
            contract,
        )
        if reevaluated.disposition is not AutonomyDisposition.AUTO_ELIGIBLE:
            raise PermissionError(
                "autonomous policy no longer permits queueing: " + ",".join(reevaluated.reason_codes)
            )
        return profile, assessment

    def _execution_authorization(self, task: Any, *, approval_verifier: Any,
                                 autonomy_profile_verifier: Any, impact_verifier: Any,
                                 active_concurrency: int) -> dict[str, Any]:
        """Re-derive an exact operator or standing-policy authorization."""
        decision = json.loads(task["decision_json"])
        mode = decision.get("authorization_mode", "operator_approval")
        if mode == "standing_policy":
            queued = decision.get("autonomous_queue")
            if (not isinstance(queued, dict) or not isinstance(queued.get("authorization_id"), str)
                    or autonomy_profile_verifier is None or impact_verifier is None):
                raise PermissionError("standing-policy authorization record or trusted verifiers are unavailable")
            try:
                UUID(queued["authorization_id"])
            except ValueError as exc:
                raise PermissionError("standing-policy authorization_id is invalid") from exc
            profile, assessment = self._revalidate_autonomous_task(
                task, autonomy_profile_verifier=autonomy_profile_verifier,
                impact_verifier=impact_verifier, active_concurrency=active_concurrency,
            )
            if (queued.get("policy_digest") != profile.policy_digest
                    or queued.get("impact_assessment_digest") != assessment.assessment_digest):
                raise PermissionError("standing-policy authorization digests no longer match retained evidence")
            return {
                "authorization_mode": "standing_policy",
                "authorization_id": queued["authorization_id"],
                "approval_id": None,
                "policy_digest": profile.policy_digest,
                "impact_assessment_digest": assessment.assessment_digest,
            }
        if mode != "operator_approval":
            raise PermissionError("task authorization mode is unsupported")
        approval_data = decision.get("approval")
        signed_record = approval_data.get("signed_record") if isinstance(approval_data, dict) else None
        if not isinstance(signed_record, dict) or not task["approval_ref"]:
            raise PermissionError("queued task has no retained signed approval record")
        if approval_verifier is None:
            raise PermissionError("trusted signed-approval verifier is unavailable")
        targets = json.loads(task["target_ids_json"])
        if len(targets) != 1:
            raise PermissionError("execution authorization requires exactly one target")
        approval = approval_verifier.verify(signed_record, expected_scope={
            "tenant_id": task["tenant_id"], "target": targets[0],
            "action": task["operation_id"], "environment": task["environment"],
            "capabilities": ["task.execute", f"plan.sha256:{task['plan_digest']}"],
            "plan_id": task["task_id"],
        })
        if (approval.get("approval_id") != task["approval_ref"]
                or approval.get("request_id") != task["goal_id"]):
            raise PermissionError("retained approval no longer matches queued task")
        return {
            "authorization_mode": "operator_approval",
            "authorization_id": task["approval_ref"],
            "approval_id": task["approval_ref"],
            "policy_digest": None,
            "impact_assessment_digest": None,
        }

    def claim_execution_lease(self, *, task_id: str, tenant_id: str, worker_id: str,
                              approval_verifier: Any = None, autonomy_profile_verifier: Any = None,
                              impact_verifier: Any = None, lease_seconds: int = 60) -> dict[str, Any]:
        if not isinstance(worker_id, str) or not worker_id.strip() or len(worker_id) > 128:
            raise ValueError("worker_id must be a non-empty bounded identifier")
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 600:
            raise ValueError("execution lease must be between 1 and 600 seconds")
        with self._lock:
            task = self._db.execute(
                "SELECT * FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id),
            ).fetchone()
        if not task:
            raise KeyError("task not found in tenant scope")
        if task["status"] != "queued" or task["environment"] in {"production", "regulated"}:
            raise PermissionError("only an authorized, queued non-production task can be leased")
        targets = json.loads(task["target_ids_json"])
        self._assert_stored_plan(task, targets)
        active_queued = self._db.execute(
            "SELECT COUNT(*) AS count FROM tasks WHERE tenant_id=? AND task_id<>? "
            "AND status IN ('queued','leased','running','verification')",
            (tenant_id, task_id),
        ).fetchone()["count"]
        authorization = self._execution_authorization(
            task, approval_verifier=approval_verifier,
            autonomy_profile_verifier=autonomy_profile_verifier,
            impact_verifier=impact_verifier, active_concurrency=active_queued,
        )
        with self._transaction():
            current = self._db.execute(
                "SELECT * FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id),
            ).fetchone()
            if (not current or current["status"] != "queued" or current["approval_ref"] != task["approval_ref"]
                    or current["plan_digest"] != task["plan_digest"] or current["decision_json"] != task["decision_json"]):
                raise PermissionError("queued task changed while its authorization was revalidated")
            active = self._db.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE tenant_id=? AND task_id<>? AND status IN ('leased','running','verification') AND lease_stage='execution'",
                (tenant_id, task_id),
            ).fetchone()["count"]
            if active:
                raise PermissionError("tenant execution concurrency limit is one active task")
            rechecked_queued = self._db.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE tenant_id=? AND task_id<>? "
                "AND status IN ('queued','leased','running','verification')",
                (tenant_id, task_id),
            ).fetchone()["count"]
            current_authorization = self._execution_authorization(
                current, approval_verifier=approval_verifier,
                autonomy_profile_verifier=autonomy_profile_verifier,
                impact_verifier=impact_verifier, active_concurrency=rechecked_queued,
            )
            if current_authorization != authorization:
                raise PermissionError("authorization changed during execution-lease claim")
            generation = current["lease_generation"] + 1
            now = datetime.now(timezone.utc)
            until = datetime.fromtimestamp(now.timestamp() + lease_seconds, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            deadline = datetime.fromtimestamp(now.timestamp() + 1800, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            token = str(uuid4())
            self._db.execute(
                "UPDATE tasks SET status='leased',lease_owner=?,lease_until=?,lease_token=?,lease_stage='execution',lease_generation=?,execution_deadline=?,updated_at=? WHERE task_id=? AND tenant_id=?",
                (worker_id, until, token, generation, deadline, _now(), task_id, tenant_id),
            )
            self._append_event(tenant_id, task["goal_id"], task_id, "task.execution_lease_claimed", {
                "worker_id": worker_id, "lease_generation": generation, "lease_until": until,
                "execution_deadline": deadline, **authorization, "execution_permitted": False,
            })
        return self.get_task(task_id=task_id, tenant_id=tenant_id) | {
                "lease_token": token, "lease_generation": generation,
            }

    def issue_execution_grant(self, *, task_id: str, tenant_id: str, lease_token: str,
                              approval_verifier: Any = None, autonomy_profile_verifier: Any = None,
                              impact_verifier: Any = None, grant_signer: Any = None,
                              grant_verifier: Any = None, execution_control: Any = None) -> dict[str, Any]:
        """Issue a runner capability from a live revalidated authorization and lease."""
        if (grant_signer is None or grant_verifier is None
                or execution_control is None):
            raise PermissionError("grant signer, grant verifier, and root kill switch are required")
        with self._transaction():
            task = self._current_execution_lease(task_id, tenant_id, lease_token, {"leased"})
            control_digest = execution_control.assert_enabled()
            if (not isinstance(control_digest, str) or len(control_digest) != 64
                    or any(character not in "0123456789abcdef" for character in control_digest)):
                raise PermissionError("execution-control verifier returned an invalid digest")
            target_ids = json.loads(task["target_ids_json"])
            if len(target_ids) != 1:
                raise PermissionError("execution grant issuance requires exactly one authorized target")
            breaker = self._db.execute(
                "SELECT state,reason FROM circuit_breakers WHERE tenant_id=? AND target_id=? AND operation_id=?",
                (tenant_id, target_ids[0], task["operation_id"]),
            ).fetchone()
            if breaker and breaker["state"] == "open":
                raise PermissionError(f"execution circuit breaker is open: {breaker['reason']}")
            self._assert_stored_plan(task, target_ids)
            active_queued = self._db.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE tenant_id=? AND task_id<>? "
                "AND status IN ('queued','leased','running','verification')",
                (tenant_id, task_id),
            ).fetchone()["count"]
            authorization = self._execution_authorization(
                task, approval_verifier=approval_verifier,
                autonomy_profile_verifier=autonomy_profile_verifier,
                impact_verifier=impact_verifier, active_concurrency=active_queued,
            )
            token_digest = hashlib.sha256(lease_token.encode("utf-8")).hexdigest()
            claims = {
                "task_id": task_id,
                "tenant_id": tenant_id,
                "target_id": target_ids[0],
                "operation_id": task["operation_id"],
                "environment": task["environment"],
                "plan_digest": task["plan_digest"],
                **authorization,
                "lease_generation": task["lease_generation"],
                "runner_id": task["lease_owner"],
                "lease_token_sha256": token_digest,
            }
            prior = self._db.execute(
                "SELECT grant_id,envelope_json,grant_sha256,expires_at,consumed_at FROM execution_grants WHERE task_id=? AND lease_generation=?",
                (task_id, task["lease_generation"]),
            ).fetchone()
            if prior:
                if prior["consumed_at"] is not None:
                    raise PermissionError("execution grant has already been consumed")
                envelope = json.loads(prior["envelope_json"])
                grant, digest = grant_verifier.verify(envelope, expected_claims=claims)
                if (grant.get("grant_id") != prior["grant_id"] or digest != prior["grant_sha256"]
                        or grant.get("expires_at") != prior["expires_at"]):
                    raise PermissionError("stored execution grant integrity verification failed")
                return {
                    "grant": envelope, "grant_sha256": digest, "expires_at": grant["expires_at"],
                    "execution_control_sha256": control_digest, "execution_permitted": False,
                }

            now = datetime.now(timezone.utc)
            hard_deadline = datetime.fromisoformat(task["execution_deadline"].replace("Z", "+00:00"))
            lease_deadline = datetime.fromisoformat(task["lease_until"].replace("Z", "+00:00"))
            stored_plan = json.loads(task["plan_json"])
            requested_runtime = min(int(stored_plan["max_runtime_seconds"]), 300)
            expires = min(
                datetime.fromtimestamp(now.timestamp() + requested_runtime, timezone.utc),
                hard_deadline, lease_deadline,
            )
            if expires <= now:
                raise PermissionError("execution lease expires before a grant can be issued")
            grant_body = {
                "schema_version": "a2z-execution-grant-v2",
                "grant_id": str(uuid4()),
                **claims,
                "issued_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
                "expires_at": expires.isoformat(timespec="seconds").replace("+00:00", "Z"),
                "max_runtime_seconds": requested_runtime,
            }
            envelope = grant_signer.sign(grant_body)
            verified_grant, digest = grant_verifier.verify(envelope, expected_claims=claims)
            if verified_grant != grant_body:
                raise PermissionError("signed execution grant differs from the authorized lease")
            self._db.execute(
                "INSERT INTO execution_grants (grant_id,task_id,tenant_id,lease_generation,envelope_json,grant_sha256,expires_at,issued_at) VALUES (?,?,?,?,?,?,?,?)",
                (grant_body["grant_id"], task_id, tenant_id, task["lease_generation"],
                 _canonical(envelope).decode(), digest, grant_body["expires_at"], grant_body["issued_at"]),
            )
            self._append_event(tenant_id, task["goal_id"], task_id, "task.execution_grant_issued", {
                "grant_id": grant_body["grant_id"], "grant_sha256": digest,
                "target_id": target_ids[0], "operation_id": task["operation_id"],
                "lease_generation": task["lease_generation"], "runner_id": task["lease_owner"],
                **authorization, "expires_at": grant_body["expires_at"],
                "execution_control_sha256": control_digest, "execution_permitted": False,
            })
            return {
                "grant": envelope, "grant_sha256": digest, "expires_at": grant_body["expires_at"],
                "execution_control_sha256": control_digest, "execution_permitted": False,
            }

    def _assert_stored_plan(self, task: Any, target_ids: list[str]) -> None:
        try:
            plan = json.loads(task["plan_json"], object_pairs_hook=_unique_pairs)
            plan_json, digest = self._validate_plan(
                plan, operation_id=task["operation_id"], target_ids=tuple(target_ids),
                environment=task["environment"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PermissionError("stored task plan is invalid or does not match task scope") from exc
        if plan_json != task["plan_json"] or digest != task["plan_digest"]:
            raise PermissionError("stored task plan digest verification failed")

    def start_leased_task(self, *, task_id: str, tenant_id: str, lease_token: str,
                          authenticated_runner_id: str, approval_verifier: Any = None,
                          autonomy_profile_verifier: Any = None, impact_verifier: Any = None,
                          expected_grant_digest: str | None = None,
                          grant_verifier: Any, execution_control: Any) -> dict[str, Any]:
        """Atomically consume a verified one-shot permit and start the journal state.

        This does not dispatch the task. Callers must derive authenticated_runner_id
        from the runner's workload identity, never from the task request body.
        """
        if grant_verifier is None or execution_control is None:
            raise PermissionError("grant verifier and root kill switch are required")
        if (not isinstance(authenticated_runner_id, str) or not authenticated_runner_id.strip()
                or len(authenticated_runner_id) > 256 or authenticated_runner_id == "*"):
            raise PermissionError("authenticated runner identity must be specific")
        with self._transaction():
            task = self._current_execution_lease(task_id, tenant_id, lease_token, {"leased"})
            if task["lease_owner"] != authenticated_runner_id:
                raise PermissionError("authenticated runner does not own the active lease")
            control_digest = execution_control.assert_enabled()
            if (not isinstance(control_digest, str) or len(control_digest) != 64
                    or any(character not in "0123456789abcdef" for character in control_digest)):
                raise PermissionError("execution-control verifier returned an invalid digest")
            if task["operation_id"] not in TRUSTED_OPERATION_CONTRACTS:
                raise PermissionError("operation is not present in the code-owned runner catalog")
            target_ids = json.loads(task["target_ids_json"])
            self._assert_stored_plan(task, target_ids)
            plan = json.loads(task["plan_json"], object_pairs_hook=_unique_pairs)
            plan_reasons = validate_operation_plan(task["operation_id"], plan)
            if plan_reasons:
                raise PermissionError("task plan failed code-owned validation: " + ",".join(plan_reasons))
            if len(target_ids) != 1:
                raise PermissionError("execution permit consumption requires one exact target")
            breaker = self._db.execute(
                "SELECT state,reason FROM circuit_breakers WHERE tenant_id=? AND target_id=? AND operation_id=?",
                (tenant_id, target_ids[0], task["operation_id"]),
            ).fetchone()
            if breaker and breaker["state"] == "open":
                raise PermissionError(f"execution circuit breaker is open: {breaker['reason']}")

            active_queued = self._db.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE tenant_id=? AND task_id<>? "
                "AND status IN ('queued','leased','running','verification')",
                (tenant_id, task_id),
            ).fetchone()["count"]
            authorization = self._execution_authorization(
                task, approval_verifier=approval_verifier,
                autonomy_profile_verifier=autonomy_profile_verifier,
                impact_verifier=impact_verifier, active_concurrency=active_queued,
            )

            grant_row = self._db.execute(
                "SELECT grant_id,envelope_json,grant_sha256,expires_at,consumed_at,consumed_by "
                "FROM execution_grants WHERE task_id=? AND tenant_id=? AND lease_generation=?",
                (task_id, tenant_id, task["lease_generation"]),
            ).fetchone()
            if not grant_row:
                raise PermissionError("active lease has no signed execution grant")
            if grant_row["consumed_at"] is not None:
                raise PermissionError("execution grant has already been consumed")
            claims = {
                "task_id": task_id, "tenant_id": tenant_id, "target_id": target_ids[0],
                "operation_id": task["operation_id"], "environment": task["environment"],
                "plan_digest": task["plan_digest"], **authorization,
                "lease_generation": task["lease_generation"], "runner_id": authenticated_runner_id,
                "lease_token_sha256": hashlib.sha256(lease_token.encode("utf-8")).hexdigest(),
            }
            envelope = json.loads(grant_row["envelope_json"])
            grant, grant_digest = grant_verifier.verify(envelope, expected_claims=claims)
            if (grant.get("grant_id") != grant_row["grant_id"]
                    or grant_digest != grant_row["grant_sha256"]
                    or grant.get("expires_at") != grant_row["expires_at"]):
                raise PermissionError("stored execution grant integrity verification failed")
            if (expected_grant_digest is not None
                    and (not isinstance(expected_grant_digest, str)
                         or not re.fullmatch(r"[0-9a-f]{64}", expected_grant_digest)
                         or expected_grant_digest != grant_digest)):
                raise PermissionError("requested one-shot permit digest does not match the active grant")
            lease_until = datetime.fromisoformat(task["lease_until"].replace("Z", "+00:00"))
            grant_until = datetime.fromisoformat(grant["expires_at"].replace("Z", "+00:00"))
            if grant_until > lease_until or grant["max_runtime_seconds"] > plan["max_runtime_seconds"]:
                raise PermissionError("execution grant exceeds lease or task plan bounds")

            stamp = _now()
            consumed = self._db.execute(
                "UPDATE execution_grants SET consumed_at=?,consumed_by=? "
                "WHERE grant_id=? AND consumed_at IS NULL",
                (stamp, authenticated_runner_id, grant_row["grant_id"]),
            )
            if consumed.rowcount != 1:
                raise PermissionError("execution grant was concurrently consumed")
            self._db.execute("UPDATE tasks SET status='running',updated_at=? WHERE task_id=?", (stamp, task_id))
            self._append_event(tenant_id, task["goal_id"], task_id, "task.execution_started", {
                "lease_generation": task["lease_generation"], "runner_id": authenticated_runner_id,
                "grant_id": grant_row["grant_id"], "grant_sha256": grant_digest,
                "authorization_mode": authorization["authorization_mode"],
                "authorization_id": authorization["authorization_id"],
                "execution_control_sha256": control_digest, "permit_consumed": True,
                "execution_permitted": False,
            })
            return self.get_task(task_id=task_id, tenant_id=tenant_id) | {
                "permit_consumed": True, "grant_digest": grant_digest,
                "execution_permitted": False,
            }

    def get_current_execution_lease(self, *, task_id: str, tenant_id: str, runner_id: str,
                                    approval_verifier: Any = None,
                                    autonomy_profile_verifier: Any = None,
                                    impact_verifier: Any = None) -> dict[str, Any]:
        """Return fresh runner-scoped lease claims for an authenticated worker adapter.

        The caller must establish runner_id and tenant_id from a mutually
        authenticated workload identity before calling this method. This method
        itself is not a network authentication mechanism.
        """
        with self._lock:
            task = self._db.execute(
                "SELECT * FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id),
            ).fetchone()
            if not task:
                raise KeyError("task not found in tenant scope")
            if (task["status"] != "leased" or task["lease_stage"] != "execution"
                    or task["lease_owner"] != runner_id or not task["lease_token"]
                    or not task["lease_until"] or task["lease_until"] <= _now()):
                raise PermissionError("runner has no current unexpired execution lease for this task")
            target_ids = json.loads(task["target_ids_json"])
            if len(target_ids) != 1:
                raise PermissionError("runner lease requires exactly one target")
            active_queued = self._db.execute(
                "SELECT COUNT(*) AS count FROM tasks WHERE tenant_id=? AND task_id<>? "
                "AND status IN ('queued','leased','running','verification')",
                (tenant_id, task_id),
            ).fetchone()["count"]
            authorization = self._execution_authorization(
                task, approval_verifier=approval_verifier,
                autonomy_profile_verifier=autonomy_profile_verifier,
                impact_verifier=impact_verifier, active_concurrency=active_queued,
            )
            return {
                "task_id": task_id, "tenant_id": tenant_id, "target_id": target_ids[0],
                "operation_id": task["operation_id"], "environment": task["environment"],
                "plan_digest": task["plan_digest"], **authorization,
                "lease_generation": task["lease_generation"], "runner_id": runner_id,
                "lease_token": task["lease_token"], "status": task["status"],
                "lease_stage": task["lease_stage"], "lease_until": task["lease_until"],
                "plan": json.loads(task["plan_json"], object_pairs_hook=_unique_pairs),
            }

    def get_current_execution_token(self, *, task_id: str, tenant_id: str,
                                    runner_id: str) -> dict[str, Any]:
        """Return a runner-owned lease token for receipt/renewal calls only."""
        with self._lock:
            task = self._db.execute(
                "SELECT status,lease_stage,lease_owner,lease_token,lease_until,lease_generation "
                "FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id),
            ).fetchone()
            if not task:
                raise KeyError("task not found in tenant scope")
            if (task["status"] not in {"leased", "running", "verification"}
                    or task["lease_stage"] != "execution" or task["lease_owner"] != runner_id
                    or not task["lease_token"] or not task["lease_until"]
                    or task["lease_until"] <= _now()):
                raise PermissionError("runner has no current active execution token")
            return {
                "lease_token": task["lease_token"], "lease_generation": task["lease_generation"],
                "status": task["status"],
            }

    def renew_execution_lease(self, *, task_id: str, tenant_id: str, lease_token: str,
                              lease_seconds: int = 60) -> dict[str, Any]:
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 600:
            raise ValueError("execution lease renewal must be between 1 and 600 seconds")
        with self._transaction():
            task = self._current_execution_lease(task_id, tenant_id, lease_token, {"leased", "running", "verification"})
            now = datetime.now(timezone.utc)
            if not task["execution_deadline"] or task["execution_deadline"] <= _now():
                raise PermissionError("task execution deadline has elapsed")
            requested_until = datetime.fromtimestamp(now.timestamp() + lease_seconds, timezone.utc)
            deadline = datetime.fromisoformat(task["execution_deadline"].replace("Z", "+00:00"))
            until = min(requested_until, deadline).isoformat(timespec="seconds").replace("+00:00", "Z")
            self._db.execute("UPDATE tasks SET lease_until=?,updated_at=? WHERE task_id=?", (until, _now(), task_id))
            self._append_event(tenant_id, task["goal_id"], task_id, "task.execution_lease_renewed", {
                "lease_generation": task["lease_generation"], "lease_until": until,
            })
            return self.get_task(task_id=task_id, tenant_id=tenant_id) | {"lease_until": until}

    def begin_task_verification(self, *, task_id: str, tenant_id: str, lease_token: str,
                                runner_receipt_digest: str) -> dict[str, Any]:
        if len(runner_receipt_digest) != 64 or any(c not in "0123456789abcdef" for c in runner_receipt_digest):
            raise ValueError("runner receipt digest must be a lowercase SHA-256 digest")
        with self._transaction():
            task = self._current_execution_lease(task_id, tenant_id, lease_token, {"running"})
            self._db.execute("UPDATE tasks SET status='verification',updated_at=? WHERE task_id=?", (_now(), task_id))
            self._append_event(tenant_id, task["goal_id"], task_id, "task.verification_started", {
                "lease_generation": task["lease_generation"], "runner_receipt_sha256": runner_receipt_digest,
            })
            return self.get_task(task_id=task_id, tenant_id=tenant_id)

    def record_runner_attestation(self, *, task_id: str, tenant_id: str, lease_token: str,
                                  signed_attestation: dict[str, Any], verifier: Any) -> dict[str, Any]:
        """Persist a verified runner receipt without treating it as proof of desired state."""
        if verifier is None or not isinstance(signed_attestation, dict):
            raise PermissionError("a trusted runner-attestation verifier and signed envelope are required")
        with self._transaction():
            task = self._current_execution_lease(task_id, tenant_id, lease_token, {"running", "verification"})
            envelope_body = signed_attestation.get("attestation")
            if not isinstance(envelope_body, dict):
                raise ValueError("signed runner attestation has no attestation body")
            target_id = envelope_body.get("target_id")
            targets = json.loads(task["target_ids_json"])
            if target_id not in targets:
                raise PermissionError("runner attestation target is outside the leased task")
            expected_claims = {
                "task_id": task_id,
                "tenant_id": tenant_id,
                "target_id": target_id,
                "operation_id": task["operation_id"],
                "environment": task["environment"],
                "plan_digest": task["plan_digest"],
                "lease_generation": task["lease_generation"],
                "runner_id": task["lease_owner"],
            }
            attestation, digest = verifier.verify(signed_attestation, expected_claims=expected_claims)
            if not isinstance(attestation, dict) or any(attestation.get(key) != value for key, value in expected_claims.items()):
                raise PermissionError("verified runner attestation does not match the active task lease")
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)):
                raise ValueError("runner-attestation verifier returned an invalid digest")
            verification_event = self._db.execute(
                "SELECT payload_json FROM goal_events WHERE task_id=? AND event_type='task.verification_started' ORDER BY sequence DESC LIMIT 1",
                (task_id,),
            ).fetchone()
            if task["status"] == "running":
                stamp = _now()
                self._db.execute(
                    "UPDATE tasks SET status='verification',updated_at=? WHERE task_id=? AND tenant_id=?",
                    (stamp, task_id, tenant_id),
                )
                self._append_event(tenant_id, task["goal_id"], task_id, "task.verification_started", {
                    "lease_generation": task["lease_generation"], "runner_receipt_sha256": digest,
                    "source": "atomic_signed_runner_attestation",
                })
            elif (not verification_event
                    or json.loads(verification_event["payload_json"]).get("runner_receipt_sha256") != digest):
                raise PermissionError("verified runner-attestation digest does not match the verification record")
            receipt_id = attestation.get("receipt_id")
            if not isinstance(receipt_id, str) or not receipt_id:
                raise ValueError("verified runner attestation has no receipt ID")
            existing = self._db.execute(
                "SELECT receipt_id,envelope_json,attestation_sha256 FROM runner_attestations "
                "WHERE task_id=? AND lease_generation=? AND target_id=?",
                (task_id, task["lease_generation"], target_id),
            ).fetchone()
            if existing:
                if (existing["receipt_id"] != receipt_id
                        or existing["attestation_sha256"] != digest
                        or existing["envelope_json"] != _canonical(signed_attestation).decode()):
                    raise PermissionError("a different runner receipt was already recorded for this target and lease")
                return {
                    "receipt_id": receipt_id, "task_id": task_id, "tenant_id": tenant_id,
                    "target_id": target_id, "lease_generation": task["lease_generation"],
                    "attestation_sha256": digest, "status": "verified_evidence_only",
                    "execution_permitted": False, "postcondition_verified": False,
                    "idempotent_replay": True,
                }
            try:
                self._db.execute(
                    "INSERT INTO runner_attestations (receipt_id,task_id,tenant_id,target_id,lease_generation,envelope_json,attestation_sha256,recorded_at) VALUES (?,?,?,?,?,?,?,?)",
                    (receipt_id, task_id, tenant_id, target_id, task["lease_generation"],
                     _canonical(signed_attestation).decode(), digest, _now()),
                )
            except sqlite3.IntegrityError as exc:
                raise PermissionError("runner receipt was already recorded for this target and lease") from exc
            self._append_event(tenant_id, task["goal_id"], task_id, "task.runner_attestation_verified", {
                "receipt_id": receipt_id, "target_id": target_id,
                "lease_generation": task["lease_generation"], "attestation_sha256": digest,
                "outcome": attestation.get("outcome"), "changed": attestation.get("changed"),
                "execution_permitted": False, "postcondition_verified": False,
            })
            if (attestation.get("outcome") in {"failed", "unknown"}
                    or attestation.get("credentials_issued") is True
                    or attestation.get("network_calls", 0) != 0):
                if attestation.get("outcome") in {"failed", "unknown"}:
                    reason = "runner reported an unknown or failed outcome"
                elif attestation.get("credentials_issued") is True:
                    reason = "runner reported credential issuance outside the grant contract"
                else:
                    reason = "runner reported network activity outside the zero-network execution contract"
                self._trip_circuit_breaker(
                    tenant_id=tenant_id, goal_id=task["goal_id"], task_id=task_id,
                    target_id=target_id, operation_id=task["operation_id"],
                    environment=task["environment"], receipt_id=receipt_id, reason=reason,
                )
            return {
                "receipt_id": receipt_id, "task_id": task_id, "tenant_id": tenant_id,
                "target_id": target_id, "lease_generation": task["lease_generation"],
                "attestation_sha256": digest, "status": "verified_evidence_only",
                "execution_permitted": False, "postcondition_verified": False,
            }

    def reconcile_late_runner_attestation(self, *, task_id: str, tenant_id: str,
                                          runner_id: str, signed_attestation: dict[str, Any],
                                          verifier: Any) -> dict[str, Any]:
        """Reconcile a signed receipt for an expired lease without reopening execution."""
        if (verifier is None or not callable(getattr(verifier, "verify_historical", None))
                or not isinstance(signed_attestation, dict)):
            raise PermissionError("historical receipt verification is required for reconciliation")
        with self._transaction():
            task = self._db.execute(
                "SELECT * FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id),
            ).fetchone()
            if not task:
                raise KeyError("task not found in tenant scope")
            self.verify_events(goal_id=task["goal_id"], tenant_id=tenant_id)
            targets = json.loads(task["target_ids_json"])
            if len(targets) != 1:
                raise PermissionError("late receipt reconciliation requires exactly one task target")
            target_id = targets[0]
            self._assert_stored_plan(task, targets)
            expected_claims = {
                "task_id": task_id, "tenant_id": tenant_id, "target_id": target_id,
                "operation_id": task["operation_id"], "environment": task["environment"],
                "plan_digest": task["plan_digest"], "lease_generation": task["lease_generation"],
                "runner_id": runner_id,
            }
            attestation, digest = verifier.verify_historical(
                signed_attestation, expected_claims=expected_claims,
            )
            if (not isinstance(attestation, dict)
                    or any(attestation.get(key) != value for key, value in expected_claims.items())):
                raise PermissionError("historical runner receipt is outside this task and runner scope")
            try:
                receipt_id = str(UUID(attestation["receipt_id"]))
            except (KeyError, ValueError, TypeError, AttributeError) as exc:
                raise ValueError("historical runner receipt ID must be a UUID") from exc
            if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValueError("historical receipt verifier returned an invalid digest")

            existing = self._db.execute(
                "SELECT receipt_id,envelope_json,attestation_sha256 FROM runner_attestations "
                "WHERE task_id=? AND lease_generation=? AND target_id=?",
                (task_id, task["lease_generation"], target_id),
            ).fetchone()
            serialized = _canonical(signed_attestation).decode()
            if existing:
                if (existing["receipt_id"] != receipt_id or existing["envelope_json"] != serialized
                        or existing["attestation_sha256"] != digest):
                    raise PermissionError("a conflicting receipt already exists for this task lease")
                task_status = task["status"]
                if task_status == "blocked":
                    last_event = self._db.execute(
                        "SELECT event_type,payload_json FROM goal_events WHERE task_id=? ORDER BY event_no DESC LIMIT 1",
                        (task_id,),
                    ).fetchone()
                    expiry = (json.loads(last_event["payload_json"], object_pairs_hook=_unique_pairs)
                              if last_event and last_event["event_type"] == "task.execution_lease_expired_blocked"
                              else {})
                    if (expiry.get("prior_status") == "verification"
                            and expiry.get("lease_generation") == task["lease_generation"]):
                        self._db.execute(
                            "UPDATE tasks SET status='verification',updated_at=? WHERE task_id=? AND tenant_id=?",
                            (_now(), task_id, tenant_id),
                        )
                        self._append_event(tenant_id, task["goal_id"], task_id,
                                           "task.verification_resumed_for_postcondition", {
                                               "lease_generation": task["lease_generation"],
                                               "runner_receipt_sha256": digest,
                                               "source": "idempotent_late_receipt_reconciliation",
                                               "execution_permitted": False,
                                           })
                        task_status = "verification"
                return {
                    "receipt_id": receipt_id, "task_id": task_id, "tenant_id": tenant_id,
                    "target_id": target_id, "lease_generation": task["lease_generation"],
                    "attestation_sha256": digest, "status": "verified_evidence_only",
                    "execution_permitted": False, "postcondition_verified": False,
                    "idempotent_replay": True, "task_status": task_status,
                }

            events = self._db.execute(
                "SELECT event_type,payload_json,created_at FROM goal_events "
                "WHERE task_id=? ORDER BY event_no", (task_id,),
            ).fetchall()
            generation = task["lease_generation"]
            generation_events: dict[str, sqlite3.Row] = {}
            for event in events:
                payload = json.loads(event["payload_json"], object_pairs_hook=_unique_pairs)
                if payload.get("lease_generation") == generation:
                    generation_events[event["event_type"]] = event
            claim = generation_events.get("task.execution_lease_claimed")
            started = generation_events.get("task.execution_started")
            grant_event = generation_events.get("task.execution_grant_issued")
            latest = events[-1] if events else None
            if not claim or not started or not grant_event:
                raise PermissionError("journal lacks the exact consumed execution history for this receipt")
            claim_payload = json.loads(claim["payload_json"], object_pairs_hook=_unique_pairs)
            started_payload = json.loads(started["payload_json"], object_pairs_hook=_unique_pairs)
            grant_payload = json.loads(grant_event["payload_json"], object_pairs_hook=_unique_pairs)
            lease_deadline = claim_payload.get("lease_until")
            renewed = generation_events.get("task.execution_lease_renewed")
            if renewed:
                lease_deadline = json.loads(renewed["payload_json"], object_pairs_hook=_unique_pairs).get("lease_until")
            expired_block = None
            if task["status"] == "blocked" and latest and latest["event_type"] == "task.execution_lease_expired_blocked":
                expired_block = json.loads(latest["payload_json"], object_pairs_hook=_unique_pairs)
                if (expired_block.get("lease_generation") != generation
                        or expired_block.get("prior_status") not in {"running", "verification"}
                        or expired_block.get("lease_until") != lease_deadline):
                    raise PermissionError("blocked task does not match its journaled expired lease")
            elif (task["status"] in {"running", "verification"}
                    and task["lease_stage"] == "execution"
                    and task["lease_owner"] == runner_id
                    and task["lease_until"] == lease_deadline
                    and task["lease_until"] and task["lease_until"] <= _now()):
                # An authenticated runner may reconcile its exact signed receipt directly.
                # The expiry transition and evidence acceptance are committed atomically below.
                expired_block = {"prior_status": task["status"], "lease_generation": generation,
                                 "lease_until": lease_deadline}
            else:
                raise PermissionError("task is not in the exact expired-lease reconciliation state")
            if (claim_payload.get("worker_id") != runner_id
                    or started_payload.get("runner_id") != runner_id
                    or started_payload.get("grant_id") != grant_payload.get("grant_id")):
                raise PermissionError("receipt runner does not match the journaled consumed lease")
            grant = self._db.execute(
                "SELECT envelope_json,grant_sha256,expires_at,consumed_at,consumed_by "
                "FROM execution_grants WHERE task_id=? AND tenant_id=? AND lease_generation=?",
                (task_id, tenant_id, generation),
            ).fetchone()
            if (not grant or not grant["consumed_at"] or grant["consumed_by"] != runner_id
                    or grant["grant_sha256"] != grant_payload.get("grant_sha256")):
                raise PermissionError("receipt has no matching consumed, journaled execution grant")
            grant_body = json.loads(grant["envelope_json"], object_pairs_hook=_unique_pairs).get("grant", {})
            if (grant_body.get("runner_id") != runner_id
                    or grant_body.get("lease_generation") != generation
                    or grant_body.get("task_id") != task_id
                    or grant_body.get("plan_digest") != task["plan_digest"]
                    or grant_body.get("expires_at") != grant["expires_at"]
                    or grant["expires_at"] != grant_payload.get("expires_at")
                    or grant["expires_at"] > lease_deadline):
                raise PermissionError("stored grant does not bind the expired lease and signed receipt")
            try:
                receipt_started = datetime.fromisoformat(attestation["started_at"].replace("Z", "+00:00"))
                receipt_completed = datetime.fromisoformat(attestation["completed_at"].replace("Z", "+00:00"))
                execution_started = datetime.fromisoformat(started["created_at"].replace("Z", "+00:00"))
                grant_expires = datetime.fromisoformat(grant["expires_at"].replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError) as exc:
                raise PermissionError("historical receipt or journal grant timestamps are invalid") from exc
            if (receipt_started.tzinfo is None or receipt_completed.tzinfo is None
                    or receipt_started < execution_started - timedelta(minutes=2)
                    or receipt_completed < receipt_started or receipt_completed > grant_expires + timedelta(minutes=2)
                    or receipt_completed > datetime.now(timezone.utc) + timedelta(minutes=2)):
                raise PermissionError("historical receipt timestamps fall outside its consumed grant window")

            if task["status"] != "blocked":
                self._db.execute(
                    "UPDATE tasks SET status='blocked',lease_owner=NULL,lease_until=NULL,lease_token=NULL,"
                    "lease_stage=NULL,updated_at=? WHERE task_id=? AND tenant_id=?",
                    (_now(), task_id, tenant_id),
                )
                self._append_event(tenant_id, task["goal_id"], task_id, "task.execution_lease_expired_blocked", {
                    "prior_status": expired_block["prior_status"], "lease_generation": generation,
                    "lease_until": lease_deadline,
                    "reason": "late signed receipt reconciled; automatic retry forbidden",
                })

            try:
                self._db.execute(
                    "INSERT INTO runner_attestations (receipt_id,task_id,tenant_id,target_id,lease_generation,envelope_json,attestation_sha256,recorded_at) VALUES (?,?,?,?,?,?,?,?)",
                    (receipt_id, task_id, tenant_id, target_id, generation, serialized, digest, _now()),
                )
            except sqlite3.IntegrityError as exc:
                raise PermissionError("historical runner receipt conflicts with journal evidence") from exc
            self._append_event(tenant_id, task["goal_id"], task_id, "task.late_runner_attestation_reconciled", {
                "receipt_id": receipt_id, "target_id": target_id,
                "lease_generation": generation, "runner_id": runner_id,
                "attestation_sha256": digest, "outcome": attestation.get("outcome"),
                "changed": attestation.get("changed"), "execution_permitted": False,
                "postcondition_verified": False,
            })
            safe_success = (
                attestation.get("outcome") in {"succeeded", "already_satisfied"}
                and attestation.get("credentials_issued") is False
                and attestation.get("network_calls") == 0
            )
            if safe_success:
                self._db.execute(
                    "UPDATE tasks SET status='verification',updated_at=? WHERE task_id=? AND tenant_id=? AND status='blocked'",
                    (_now(), task_id, tenant_id),
                )
                self._append_event(tenant_id, task["goal_id"], task_id, "task.verification_resumed_for_postcondition", {
                    "lease_generation": generation, "runner_receipt_sha256": digest,
                    "source": "signed_late_receipt_reconciliation",
                    "execution_permitted": False,
                })
                status = "verification"
            else:
                reason = "late runner receipt reports failed/unknown outcome or violates zero-network grant"
                self._trip_circuit_breaker(
                    tenant_id=tenant_id, goal_id=task["goal_id"], task_id=task_id,
                    target_id=target_id, operation_id=task["operation_id"],
                    environment=task["environment"], receipt_id=receipt_id, reason=reason,
                )
                status = "blocked"
            return {
                "receipt_id": receipt_id, "task_id": task_id, "tenant_id": tenant_id,
                "target_id": target_id, "lease_generation": generation,
                "attestation_sha256": digest, "status": "verified_evidence_only",
                "task_status": status, "execution_permitted": False,
                "postcondition_verified": False,
            }

    def record_postcondition_attestation(self, *, task_id: str, tenant_id: str,
                                         signed_attestation: dict[str, Any], verifier: Any) -> dict[str, Any]:
        """Complete only from a separately signed, exact-state postcondition observation."""
        if verifier is None or not isinstance(signed_attestation, dict):
            raise PermissionError("trusted postcondition verifier and signed observation are required")
        with self._transaction():
            task = self._db.execute(
                "SELECT * FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id),
            ).fetchone()
            if not task:
                raise KeyError("task not found in tenant scope")
            body = signed_attestation.get("attestation")
            if not isinstance(body, dict):
                raise ValueError("postcondition envelope has no attestation body")
            target_id = body.get("target_id")
            targets = json.loads(task["target_ids_json"])
            if target_id not in targets or len(targets) != 1:
                raise PermissionError("postcondition target is outside the exact single-target task")
            runner_row = self._db.execute(
                "SELECT receipt_id,envelope_json,attestation_sha256 FROM runner_attestations "
                "WHERE task_id=? AND tenant_id=? AND lease_generation=? AND target_id=?",
                (task_id, tenant_id, task["lease_generation"], target_id),
            ).fetchone()
            if not runner_row:
                raise PermissionError("independent verification requires a recorded runner receipt")
            runner_envelope = json.loads(runner_row["envelope_json"])
            runner_body = runner_envelope.get("attestation", {})
            if runner_body.get("outcome") not in {"succeeded", "already_satisfied"}:
                raise PermissionError("a failed or unknown runner outcome cannot be completed by postcondition evidence")
            expected_claims = {
                "receipt_id": runner_row["receipt_id"], "task_id": task_id,
                "tenant_id": tenant_id, "target_id": target_id,
                "operation_id": task["operation_id"], "environment": task["environment"],
                "plan_digest": task["plan_digest"], "lease_generation": task["lease_generation"],
            }
            if any(body.get(key) != value for key, value in expected_claims.items()):
                raise PermissionError("signed postcondition evidence does not match the runner receipt and task")
            envelope_json = _canonical(signed_attestation).decode()
            existing = self._db.execute(
                "SELECT verification_id,envelope_json,attestation_sha256,verified "
                "FROM postcondition_attestations WHERE task_id=? AND lease_generation=?",
                (task_id, task["lease_generation"]),
            ).fetchone()
            if existing:
                verification_id = body.get("verification_id")
                try:
                    verification_id = str(UUID(verification_id))
                except (ValueError, TypeError, AttributeError) as exc:
                    raise ValueError("postcondition evidence has no valid verification UUID") from exc
                replay_digest = hashlib.sha256(_canonical({
                    "domain": "a2z.postcondition-attestation.v1", "attestation": body,
                })).hexdigest()
                if (existing["verification_id"] != verification_id
                        or existing["envelope_json"] != envelope_json
                        or existing["attestation_sha256"] != replay_digest):
                    raise PermissionError("conflicting postcondition evidence already exists for this lease")
                return {
                    "verification_id": verification_id, "task_id": task_id,
                    "status": "completed" if existing["verified"] else "blocked",
                    "verified": bool(existing["verified"]), "execution_permitted": False,
                    "idempotent_replay": True,
                }
            attestation, digest = verifier.verify(signed_attestation, expected_claims=expected_claims)
            if (not isinstance(attestation, dict)
                    or any(attestation.get(key) != value for key, value in expected_claims.items())):
                raise PermissionError("signed postcondition evidence does not match the runner receipt and task")
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)):
                raise ValueError("postcondition verifier returned an invalid digest")
            verification_id = attestation.get("verification_id")
            if not isinstance(verification_id, str) or not verification_id:
                raise ValueError("postcondition evidence has no verification ID")

            if task["status"] != "verification":
                raise PermissionError("task must be in verification before independent evidence can finalize it")

            if task["operation_id"] != "virtualbox.vm.set_demo_description":
                raise PermissionError("no independent postcondition contract is configured for this operation")
            self._assert_stored_plan(task, targets)
            plan = json.loads(task["plan_json"], object_pairs_hook=_unique_pairs)
            plan_reasons = validate_operation_plan(task["operation_id"], plan)
            if plan_reasons:
                raise PermissionError("stored plan failed postcondition contract validation")
            expected_state = {
                "power_state": "powered_off",
                "description": plan["desired_state"]["description"],
            }
            observed_state = attestation.get("observed_state")
            if not isinstance(observed_state, dict):
                raise ValueError("signed postcondition observation must include typed observed state")
            expected_digest = hashlib.sha256(_canonical(expected_state)).hexdigest()
            observed_digest = hashlib.sha256(_canonical(observed_state)).hexdigest()
            verified = observed_state == expected_state
            stamp = _now()
            try:
                self._db.execute(
                    "INSERT INTO postcondition_attestations "
                    "(verification_id,task_id,tenant_id,target_id,lease_generation,envelope_json,"
                    "attestation_sha256,expected_state_sha256,observed_state_sha256,verified,recorded_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (verification_id, task_id, tenant_id, target_id, task["lease_generation"],
                     envelope_json, digest, expected_digest, observed_digest, int(verified), stamp),
                )
            except sqlite3.IntegrityError as exc:
                raise PermissionError("postcondition evidence was already recorded for this lease") from exc

            if verified:
                self._db.execute(
                    "UPDATE tasks SET status='completed',lease_owner=NULL,lease_until=NULL,lease_token=NULL,"
                    "lease_stage=NULL,execution_deadline=NULL,updated_at=? WHERE task_id=? AND tenant_id=?",
                    (stamp, task_id, tenant_id),
                )
                self._append_event(tenant_id, task["goal_id"], task_id, "task.completed", {
                    "receipt_id": runner_row["receipt_id"], "verification_id": verification_id,
                    "runner_attestation_sha256": runner_row["attestation_sha256"],
                    "postcondition_attestation_sha256": digest,
                    "expected_state_sha256": expected_digest,
                    "observed_state_sha256": observed_digest,
                    "verifier_id": attestation["verifier_id"],
                    "execution_permitted": False, "postcondition_verified": True,
                })
                status = "completed"
            else:
                self._db.execute(
                    "UPDATE tasks SET status='blocked',lease_owner=NULL,lease_until=NULL,lease_token=NULL,"
                    "lease_stage=NULL,execution_deadline=NULL,updated_at=? WHERE task_id=? AND tenant_id=?",
                    (stamp, task_id, tenant_id),
                )
                self._append_event(tenant_id, task["goal_id"], task_id, "task.postcondition_mismatch_blocked", {
                    "receipt_id": runner_row["receipt_id"], "verification_id": verification_id,
                    "runner_attestation_sha256": runner_row["attestation_sha256"],
                    "postcondition_attestation_sha256": digest,
                    "expected_state_sha256": expected_digest,
                    "observed_state_sha256": observed_digest,
                    "verifier_id": attestation["verifier_id"],
                    "execution_permitted": False, "postcondition_verified": False,
                })
                self._trip_circuit_breaker(
                    tenant_id=tenant_id, goal_id=task["goal_id"], task_id=task_id,
                    target_id=target_id, operation_id=task["operation_id"],
                    environment=task["environment"], receipt_id=runner_row["receipt_id"],
                    reason="independent postcondition differs from exact desired state",
                )
                status = "blocked"
            return {
                "verification_id": verification_id, "task_id": task_id,
                "tenant_id": tenant_id, "target_id": target_id,
                "status": status, "verified": verified,
                "execution_permitted": False, "postcondition_verified": verified,
                "expected_state_sha256": expected_digest,
                "observed_state_sha256": observed_digest,
            }

    def _trip_circuit_breaker(self, *, tenant_id: str, goal_id: str, task_id: str,
                              target_id: str, operation_id: str, environment: str,
                              receipt_id: str, reason: str) -> None:
        current = self._db.execute(
            "SELECT state FROM circuit_breakers WHERE tenant_id=? AND target_id=? AND operation_id=?",
            (tenant_id, target_id, operation_id),
        ).fetchone()
        if current and current["state"] == "open":
            return
        stamp = _now()
        self._db.execute(
            "INSERT INTO circuit_breakers (tenant_id,target_id,operation_id,environment,state,goal_id,task_id,last_receipt_id,reason,opened_at,reset_approval_id,reset_evidence_sha256,reset_at) VALUES (?,?,?,?,'open',?,?,?,?,?,NULL,NULL,NULL) ON CONFLICT (tenant_id,target_id,operation_id) DO UPDATE SET environment=excluded.environment,state='open',goal_id=excluded.goal_id,task_id=excluded.task_id,last_receipt_id=excluded.last_receipt_id,reason=excluded.reason,opened_at=excluded.opened_at,reset_approval_id=NULL,reset_evidence_sha256=NULL,reset_at=NULL",
            (tenant_id, target_id, operation_id, environment, goal_id, task_id, receipt_id, reason, stamp),
        )
        self._append_event(tenant_id, goal_id, task_id, "task.execution_circuit_breaker_opened", {
            "target_id": target_id, "operation_id": operation_id,
            "receipt_id": receipt_id, "reason": reason,
            "execution_permitted": False,
        })

    def reset_circuit_breaker(self, *, tenant_id: str, target_id: str, operation_id: str,
                              evidence_digest: str, signed_approval: dict[str, Any],
                              approval_verifier: Any) -> dict[str, Any]:
        """Require a task-scoped signed human approval and evidence digest to reset a tripped breaker."""
        if (not isinstance(evidence_digest, str) or len(evidence_digest) != 64
                or any(character not in "0123456789abcdef" for character in evidence_digest)):
            raise ValueError("circuit-breaker reset requires a lowercase evidence SHA-256 digest")
        if approval_verifier is None or not isinstance(signed_approval, dict):
            raise PermissionError("trusted signed-approval verification is required to reset a circuit breaker")
        with self._transaction():
            breaker = self._db.execute(
                "SELECT * FROM circuit_breakers WHERE tenant_id=? AND target_id=? AND operation_id=?",
                (tenant_id, target_id, operation_id),
            ).fetchone()
            if not breaker or breaker["state"] != "open":
                raise PermissionError("no open circuit breaker exists for this exact target and operation")
            approval = approval_verifier.verify(signed_approval, expected_scope={
                "tenant_id": tenant_id,
                "target": target_id,
                "action": "control_plane.circuit_breaker.reset",
                "environment": breaker["environment"],
                "capabilities": ["circuit_breaker.reset", f"evidence.sha256:{evidence_digest}"],
                "plan_id": breaker["task_id"],
            })
            if approval.get("request_id") != breaker["goal_id"]:
                raise PermissionError("circuit-breaker reset approval is not bound to the triggering goal")
            try:
                self._db.execute(
                    "INSERT INTO consumed_approvals (approval_id,tenant_id,task_id,consumed_at) VALUES (?,?,?,?)",
                    (approval["approval_id"], tenant_id, breaker["task_id"], _now()),
                )
            except sqlite3.IntegrityError as exc:
                raise PermissionError("circuit-breaker reset approval was already consumed") from exc
            stamp = _now()
            self._db.execute(
                "UPDATE circuit_breakers SET state='closed',reset_approval_id=?,reset_evidence_sha256=?,reset_at=? WHERE tenant_id=? AND target_id=? AND operation_id=? AND state='open'",
                (approval["approval_id"], evidence_digest, stamp, tenant_id, target_id, operation_id),
            )
            self._append_event(tenant_id, breaker["goal_id"], breaker["task_id"], "task.execution_circuit_breaker_reset", {
                "target_id": target_id, "operation_id": operation_id,
                "reset_approval_id": approval["approval_id"], "approver_id": approval["approver_id"],
                "evidence_sha256": evidence_digest, "execution_permitted": False,
            })
            return {
                "tenant_id": tenant_id, "target_id": target_id, "operation_id": operation_id,
                "state": "closed", "reset_approval_id": approval["approval_id"],
                "evidence_sha256": evidence_digest, "execution_permitted": False,
            }

    def get_circuit_breaker(self, *, tenant_id: str, target_id: str, operation_id: str) -> dict[str, Any]:
        row = self._db.execute(
            "SELECT tenant_id,target_id,operation_id,environment,state,goal_id,task_id,last_receipt_id,reason,opened_at,reset_approval_id,reset_evidence_sha256,reset_at FROM circuit_breakers WHERE tenant_id=? AND target_id=? AND operation_id=?",
            (tenant_id, target_id, operation_id),
        ).fetchone()
        if not row:
            return {"tenant_id": tenant_id, "target_id": target_id, "operation_id": operation_id, "state": "closed"}
        return dict(row)

    def recover_expired_execution_lease(self, *, task_id: str, tenant_id: str) -> dict[str, Any]:
        with self._transaction():
            task = self._db.execute(
                "SELECT goal_id,status,lease_stage,lease_until,lease_generation FROM tasks WHERE task_id=? AND tenant_id=?",
                (task_id, tenant_id),
            ).fetchone()
            if not task:
                raise KeyError("task not found in tenant scope")
            if task["status"] not in {"leased", "running", "verification"} or task["lease_stage"] != "execution":
                raise PermissionError("task has no recoverable execution lease")
            if not task["lease_until"] or task["lease_until"] > _now():
                raise PermissionError("execution lease has not expired")
            prior_status = task["status"]
            self._db.execute(
                "UPDATE tasks SET status='blocked',lease_owner=NULL,lease_until=NULL,lease_token=NULL,lease_stage=NULL,updated_at=? WHERE task_id=?",
                (_now(), task_id),
            )
            self._append_event(tenant_id, task["goal_id"], task_id, "task.execution_lease_expired_blocked", {
                "prior_status": prior_status, "lease_generation": task["lease_generation"],
                "lease_until": task["lease_until"],
                "reason": "execution outcome may be uncertain; automatic retry forbidden",
            })
            return self.get_task(task_id=task_id, tenant_id=tenant_id)

    def _current_execution_lease(self, task_id: str, tenant_id: str, lease_token: str,
                                 valid_states: set[str]) -> sqlite3.Row:
        task = self._db.execute(
            "SELECT * FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id),
        ).fetchone()
        if not task:
            raise KeyError("task not found in tenant scope")
        if (task["status"] not in valid_states or task["lease_stage"] != "execution"
                or not lease_token or task["lease_token"] != lease_token
                or not task["lease_until"] or task["lease_until"] <= _now()):
            raise PermissionError("a current, unexpired fenced execution lease is required")
        return task

    def get_task(self, *, task_id: str, tenant_id: str) -> dict[str, Any]:
        row = self._db.execute("SELECT * FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id)).fetchone()
        if not row:
            raise KeyError("task not found in tenant scope")
        result = dict(row)
        result["target_ids"] = json.loads(result.pop("target_ids_json"))
        result["plan"] = json.loads(result.pop("plan_json"))
        result["decision"] = json.loads(result.pop("decision_json"))
        result.pop("lease_token", None)
        result["execution_permitted"] = False
        return result

    def get_postcondition_candidate(self, *, task_id: str, tenant_id: str) -> dict[str, Any]:
        """Return immutable journal context to a read-only independent verifier."""
        with self._lock:
            task = self._db.execute(
                "SELECT * FROM tasks WHERE task_id=? AND tenant_id=?", (task_id, tenant_id),
            ).fetchone()
            if not task:
                raise KeyError("task not found in tenant scope")
            if task["status"] != "verification":
                raise PermissionError("task is not awaiting independent postcondition verification")
            targets = json.loads(task["target_ids_json"])
            if len(targets) != 1:
                raise PermissionError("postcondition candidate must have exactly one target")
            receipt = self._db.execute(
                "SELECT envelope_json,attestation_sha256 FROM runner_attestations "
                "WHERE task_id=? AND tenant_id=? AND lease_generation=? AND target_id=?",
                (task_id, tenant_id, task["lease_generation"], targets[0]),
            ).fetchone()
            if not receipt:
                raise PermissionError("task has no verified runner receipt to independently inspect")
            return {
                "task_id": task_id, "tenant_id": tenant_id,
                "target_id": targets[0], "operation_id": task["operation_id"],
                "environment": task["environment"], "plan_digest": task["plan_digest"],
                "lease_generation": task["lease_generation"],
                "plan": json.loads(task["plan_json"], object_pairs_hook=_unique_pairs),
                "runner_attestation": json.loads(receipt["envelope_json"], object_pairs_hook=_unique_pairs),
                "runner_attestation_sha256": receipt["attestation_sha256"],
            }

    def list_postcondition_candidates(self, *, tenant_id: str, target_ids: frozenset[str],
                                      operation_ids: frozenset[str], environments: frozenset[str],
                                      limit: int = 20) -> list[dict[str, Any]]:
        """Return bounded non-secret metadata for verifier polling inside its exact scope."""
        if not isinstance(tenant_id, str) or not tenant_id.strip() or len(tenant_id) > 256:
            raise ValueError("tenant_id must be a specific bounded identifier")
        for name, values in (("target_ids", target_ids), ("operation_ids", operation_ids),
                             ("environments", environments)):
            if (not isinstance(values, frozenset) or not values or len(values) > 500
                    or any(not isinstance(value, str) or not value.strip() or value == "*" or len(value) > 512
                           for value in values)):
                raise ValueError(f"{name} must be a non-empty exact allowlist")
        if not environments.issubset({"lab", "development", "staging"}):
            raise PermissionError("postcondition environment scope includes a forbidden environment")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("postcondition candidate page size must be between 1 and 100")
        op_marks = ",".join("?" for _ in operation_ids)
        env_marks = ",".join("?" for _ in environments)
        target_marks = ",".join("?" for _ in target_ids)
        # JSON1 is required for exact single-target filtering; unsupported SQLite fails closed.
        rows = self._db.execute(
            "SELECT t.task_id,t.operation_id,json_extract(t.target_ids_json,'$[0]') AS target_id,"
            "t.environment,t.plan_digest,t.updated_at "
            "FROM tasks AS t WHERE t.tenant_id=? AND t.status='verification' "
            f"AND t.operation_id IN ({op_marks}) AND t.environment IN ({env_marks}) "
            "AND json_array_length(t.target_ids_json)=1 "
            f"AND json_extract(t.target_ids_json,'$[0]') IN ({target_marks}) "
            "AND EXISTS (SELECT 1 FROM runner_attestations AS r WHERE r.task_id=t.task_id "
            "AND r.tenant_id=t.tenant_id AND r.lease_generation=t.lease_generation "
            "AND r.target_id=json_extract(t.target_ids_json,'$[0]')) "
            "ORDER BY t.updated_at,t.task_id LIMIT ?",
            (tenant_id, *sorted(operation_ids), *sorted(environments), *sorted(target_ids), limit),
        ).fetchall()
        return [{
            "task_id": row["task_id"], "tenant_id": tenant_id, "operation_id": row["operation_id"],
            "target_id": row["target_id"], "environment": row["environment"],
            "plan_digest": row["plan_digest"], "updated_at": row["updated_at"],
        } for row in rows]

    def list_ready_execution_tasks(self, *, tenant_id: str, target_ids: frozenset[str],
                                   operation_ids: frozenset[str], environments: frozenset[str],
                                   limit: int = 50) -> list[dict[str, Any]]:
        """Return bounded metadata for queued tasks inside an enrolled runner's exact scope."""
        if not isinstance(tenant_id, str) or not tenant_id.strip() or len(tenant_id) > 256:
            raise ValueError("tenant_id must be a specific bounded identifier")
        for name, values in (("target_ids", target_ids), ("operation_ids", operation_ids), ("environments", environments)):
            if (not isinstance(values, frozenset) or not values or len(values) > 500
                    or any(not isinstance(value, str) or not value.strip() or value == "*" or len(value) > 512 for value in values)):
                raise ValueError(f"{name} must be a non-empty exact allowlist")
        if not environments.issubset({"lab", "development", "staging"}):
            raise PermissionError("ready-task environment scope includes a forbidden environment")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("ready-task page size must be between 1 and 100")
        op_marks = ",".join("?" for _ in operation_ids)
        env_marks = ",".join("?" for _ in environments)
        target_marks = ",".join("?" for _ in target_ids)
        # JSON1 is part of supported SQLite builds. If unavailable, fail closed rather
        # than returning an incompletely scoped queue view.
        rows = self._db.execute(
            "SELECT task_id,operation_id,target_ids_json,environment,plan_digest,created_at "
            "FROM tasks AS t WHERE tenant_id=? AND status='queued' "
            f"AND operation_id IN ({op_marks}) AND environment IN ({env_marks}) "
            "AND json_array_length(target_ids_json)>0 "
            "AND NOT EXISTS (SELECT 1 FROM json_each(t.target_ids_json) AS target "
            f"WHERE target.value NOT IN ({target_marks})) "
            "ORDER BY created_at,task_id LIMIT ?",
            (tenant_id, *sorted(operation_ids), *sorted(environments), *sorted(target_ids), limit),
        ).fetchall()
        return [{
            "task_id": row["task_id"], "operation_id": row["operation_id"],
            "target_ids": json.loads(row["target_ids_json"]), "environment": row["environment"],
            "plan_digest": row["plan_digest"], "created_at": row["created_at"],
        } for row in rows]

    def get_goal_status(self, *, goal_id: str, tenant_id: str) -> dict[str, Any]:
        goal = self._db.execute(
            "SELECT goal_id,tenant_id,requested_by,status,created_at FROM goals WHERE goal_id=? AND tenant_id=?",
            (goal_id, tenant_id),
        ).fetchone()
        if not goal:
            raise KeyError("goal not found in tenant scope")
        task_ids = self._db.execute(
            "SELECT task_id FROM tasks WHERE goal_id=? AND tenant_id=? ORDER BY created_at,task_id",
            (goal_id, tenant_id),
        ).fetchall()
        tasks = [self.get_task(task_id=row["task_id"], tenant_id=tenant_id) for row in task_ids]
        return {
            **dict(goal),
            "tasks": tasks,
            "event_chain": self.verify_events(goal_id=goal_id, tenant_id=tenant_id),
            "execution_permitted": False,
        }

    def events(self, *, goal_id: str, tenant_id: str) -> tuple[dict[str, Any], ...]:
        rows = self._db.execute("SELECT * FROM goal_events WHERE goal_id=? AND tenant_id=? ORDER BY sequence", (goal_id, tenant_id)).fetchall()
        return tuple({**dict(row), "payload": json.loads(row["payload_json"])} for row in rows)

    def verify_events(self, *, goal_id: str, tenant_id: str) -> dict[str, Any]:
        rows = self._db.execute("SELECT * FROM goal_events WHERE goal_id=? AND tenant_id=? ORDER BY sequence", (goal_id, tenant_id)).fetchall()
        previous = None
        for row in rows:
            unsigned = {"sequence": row["sequence"], "event_id": row["event_id"], "tenant_id": row["tenant_id"], "goal_id": row["goal_id"], "task_id": row["task_id"], "event_type": row["event_type"], "payload": json.loads(row["payload_json"]), "previous_hash": previous, "created_at": row["created_at"]}
            if row["previous_hash"] != previous or hashlib.sha256(_canonical(unsigned)).hexdigest() != row["event_hash"]:
                raise ValueError("goal event journal integrity verification failed")
            previous = row["event_hash"]
        return {"tenant_id": tenant_id, "goal_id": goal_id, "events": len(rows), "last_event_sha256": previous, "execution_permitted": False}

    def _append_event(self, tenant_id: str, goal_id: str, task_id: str | None, event_type: str, payload: dict[str, Any]) -> None:
        row = self._db.execute("SELECT sequence,event_hash FROM goal_events WHERE tenant_id=? AND goal_id=? ORDER BY sequence DESC LIMIT 1", (tenant_id, goal_id)).fetchone()
        sequence = (row["sequence"] + 1) if row else 1
        previous = row["event_hash"] if row else None
        event_id, stamp = str(uuid4()), _now()
        unsigned = {"sequence": sequence, "event_id": event_id, "tenant_id": tenant_id, "goal_id": goal_id, "task_id": task_id, "event_type": event_type, "payload": payload, "previous_hash": previous, "created_at": stamp}
        event_hash = hashlib.sha256(_canonical(unsigned)).hexdigest()
        self._db.execute(
            "INSERT INTO goal_events (sequence,event_id,tenant_id,goal_id,task_id,event_type,payload_json,previous_hash,event_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (sequence, event_id, tenant_id, goal_id, task_id, event_type, _canonical(payload).decode(), previous, event_hash, stamp),
        )

    class _Transaction:
        def __init__(self, store: "DurableGoalStore") -> None:
            self.store = store
        def __enter__(self):
            self.store._lock.acquire()
            self.store._db.execute("BEGIN IMMEDIATE")
        def __exit__(self, exc_type, exc, tb):
            try:
                self.store._db.execute("ROLLBACK" if exc_type else "COMMIT")
            finally:
                self.store._lock.release()

    def _transaction(self):
        return self._Transaction(self)
