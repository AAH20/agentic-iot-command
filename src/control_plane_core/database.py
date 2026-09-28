"""Optional pooled PostgreSQL read models and integration metadata persistence."""
from __future__ import annotations

import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


class PostgresRepository:
    def __init__(self, dsn: str) -> None:
        try:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:
            raise RuntimeError("install requirements-db.txt to enable PostgreSQL") from exc
        pool_size = int(os.environ.get("A2Z_DB_POOL_SIZE", "8"))
        if not 1 <= pool_size <= 32:
            raise ValueError("A2Z_DB_POOL_SIZE must be between 1 and 32")
        self._dict_row = dict_row
        self.pool = ConnectionPool(
            conninfo=dsn, min_size=1, max_size=pool_size, timeout=3,
            kwargs={"row_factory": dict_row, "prepare_threshold": None},
            open=True, name="opsatlas-api",
        )
        self.pool.wait(timeout=5)

    def close(self) -> None:
        self.pool.close()

    def status(self) -> dict[str, Any]:
        with self.pool.connection() as conn:
            row = conn.execute("SELECT current_database() AS database, current_setting('server_version_num') AS version").fetchone()
        return {"status": "connected", "database": row["database"], "postgres_version_num": row["version"], "execution_permitted": False}

    def readiness(self) -> dict[str, Any]:
        """Check required schema and forced tenant RLS without exposing DB identity."""
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute("SET TRANSACTION READ ONLY")
                tables = conn.execute(
                    "SELECT to_regclass('opsatlas.tenants') IS NOT NULL AS tenants, "
                    "to_regclass('opsatlas.assets') IS NOT NULL AS assets, "
                    "to_regclass('opsatlas.evidence_events') IS NOT NULL AS evidence"
                ).fetchone()
                rls = conn.execute(
                    "SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "WHERE n.nspname='opsatlas' AND c.relname=ANY(%s)",
                    (["assets", "evidence_events"],),
                ).fetchall()
        if not tables or not all(tables.values()):
            return {"ready": False, "checks": {"database": "ok", "schema": "incomplete", "tenant_rls": "unchecked"}, "execution_permitted": False}
        policies = {row["relname"]: row for row in rls}
        required = {"assets", "evidence_events"}
        if set(policies) != required or any(not row["relrowsecurity"] or not row["relforcerowsecurity"] for row in policies.values()):
            return {"ready": False, "checks": {"database": "ok", "schema": "ok", "tenant_rls": "not_enforced"}, "execution_permitted": False}
        return {"ready": True, "checks": {"database": "ok", "schema": "ok", "tenant_rls": "ok"}, "execution_permitted": False}

    def tenants(self) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            return conn.execute("SELECT id::text AS tenant_id, slug, name, status, COALESCE(metadata->>'synthetic','false')='true' AS synthetic FROM opsatlas.tenants ORDER BY name,id").fetchall()

    def create_tenant(self, slug: str, name: str) -> dict[str, Any]:
        with self.pool.connection() as conn:
            return conn.execute(
                "INSERT INTO opsatlas.tenants(slug,name) VALUES(%s,%s) RETURNING id::text AS tenant_id,slug,name,status",
                (slug,name),
            ).fetchone()

    def inventory(self, tenant_id: str) -> dict[str, list[dict[str, Any]]]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            identities = conn.execute(
                "SELECT external_id AS identity_id,tenant_id::text,identity_type AS kind,status FROM opsatlas.identities WHERE tenant_id=%s::uuid ORDER BY external_id",
                (tenant_id,),
            ).fetchall()
            assets = conn.execute(
                "SELECT external_id AS asset_id,tenant_id::text,asset_type AS kind,environment,lifecycle_state AS status,observed_at FROM opsatlas.assets WHERE tenant_id=%s::uuid ORDER BY external_id",
                (tenant_id,),
            ).fetchall()
        return {"identities": identities, "assets": assets}

    def add_identity(self, tenant_id: str, identity_id: str, kind: str) -> dict[str, Any]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            return conn.execute(
                "INSERT INTO opsatlas.identities(tenant_id,external_id,identity_type) VALUES(%s::uuid,%s,%s) "
                "RETURNING external_id AS identity_id,tenant_id::text,identity_type AS kind,status",
                (tenant_id,identity_id,kind),
            ).fetchone()

    def add_asset(self, tenant_id: str, asset_id: str, kind: str, environment: str) -> dict[str, Any]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            return conn.execute(
                "INSERT INTO opsatlas.assets(tenant_id,external_id,asset_type,environment) VALUES(%s::uuid,%s,%s,%s) "
                "RETURNING external_id AS asset_id,tenant_id::text,asset_type AS kind,environment,lifecycle_state AS status",
                (tenant_id,asset_id,kind,environment),
            ).fetchone()

    def persist_inventory_observations(self, tenant_id: str, observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Upsert a bounded read-only inventory batch and its evidence atomically."""
        if not observations or len(observations) > 1002:
            raise ValueError("inventory observation batch must contain 1-1002 records")
        seen: set[str] = set()
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
                rows: list[dict[str, Any]] = []
                for item in observations:
                    resource_id = item["resource_id"]
                    if resource_id in seen:
                        raise ValueError("inventory observation batch contains duplicate resource IDs")
                    seen.add(resource_id)
                    attributes = {**item["attributes"], "source_connector": item["source_connector"]}
                    row = conn.execute(
                        "INSERT INTO opsatlas.assets(tenant_id,external_id,asset_type,environment,attributes,observed_at) "
                        "VALUES(%s::uuid,%s,%s,%s,%s::jsonb,%s::timestamptz) "
                        "ON CONFLICT(tenant_id,external_id) DO UPDATE SET "
                        "asset_type=excluded.asset_type,environment=excluded.environment,attributes=excluded.attributes,observed_at=excluded.observed_at "
                        "RETURNING external_id AS asset_id,tenant_id::text,asset_type AS kind,environment,lifecycle_state AS status,observed_at",
                        (tenant_id,resource_id,item["resource_type"],item["environment"],
                         json.dumps(attributes,sort_keys=True,separators=(",",":")),item["observed_at"]),
                    ).fetchone()
                    rows.append(row)
                self._append_evidence_with_conn(
                    conn, tenant_id=tenant_id, event_type="inventory.observed",
                    collector="local-control-plane-api/0.1",
                    payload={"tenant_id": tenant_id, "observations": observations},
                )
        return rows

    def add_request(self, request: Any, decision: dict[str, Any]) -> None:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (request.tenant_id,))
            conn.execute(
                "INSERT INTO opsatlas.authorization_requests(id,tenant_id,actor_identity_id,target_asset_id,action,mode,environment,reason,capabilities,decision,decision_reasons,decided_at) "
                "VALUES(%s::uuid,%s::uuid,(SELECT id FROM opsatlas.identities WHERE tenant_id=%s::uuid AND external_id=%s)," 
                "(SELECT id FROM opsatlas.assets WHERE tenant_id=%s::uuid AND external_id=%s),%s,%s,%s,%s,%s,%s,%s::jsonb,now())",
                (str(request.request_id),request.tenant_id,request.tenant_id,request.actor_id,request.tenant_id,request.target,request.action,request.mode,request.environment,request.reason,list(request.capabilities),decision.get("decision","deny"),json.dumps(decision.get("reason_codes",[]))),
            )

    def requests(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            rows = conn.execute(
                "SELECT r.id::text AS request_id,r.tenant_id::text,i.external_id AS actor_id,r.action,COALESCE(a.external_id,'') AS target,r.mode,r.environment,r.capabilities,r.reason,r.decision,r.decision_reasons,r.created_at "
                "FROM opsatlas.authorization_requests r JOIN opsatlas.identities i ON i.tenant_id=r.tenant_id AND i.id=r.actor_identity_id "
                "LEFT JOIN opsatlas.assets a ON a.tenant_id=r.tenant_id AND a.id=r.target_asset_id "
                "WHERE r.tenant_id=%s::uuid ORDER BY r.created_at DESC,r.id DESC LIMIT 500",
                (tenant_id,),
            ).fetchall()
        return rows

    def add_plan(self, tenant_id: str, plan: dict[str, Any]) -> None:
        plan_id = str(plan["plan_id"])
        request_id = str(plan["request_id"])
        payload = json.dumps(plan, sort_keys=True, separators=(",", ":"), default=str)
        import hashlib
        digest = hashlib.sha256(payload.encode()).hexdigest()
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            conn.execute(
                "INSERT INTO opsatlas.change_plans(id,tenant_id,request_id,plan_digest,plan) VALUES(%s::uuid,%s::uuid,%s::uuid,%s,%s::jsonb)",
                (plan_id,tenant_id,request_id,digest,payload),
            )

    def save_change_workflow(self, *, tenant_id: str, plan: dict[str, Any], event_type: str,
                             event_payload: dict[str, Any], create: bool = False) -> None:
        """Persist a workflow snapshot and its evidence record atomically."""
        plan_id = str(plan["plan_id"])
        request_id = str(plan["request_id"])
        serialized = json.dumps(plan, sort_keys=True, separators=(",", ":"), default=str)
        digest = hashlib.sha256(serialized.encode()).hexdigest()
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
                if create:
                    conn.execute(
                        "INSERT INTO opsatlas.change_plans(id,tenant_id,request_id,plan_digest,plan,execution_permitted) "
                        "VALUES(%s::uuid,%s::uuid,%s::uuid,%s,%s::jsonb,false)",
                        (plan_id, tenant_id, request_id, digest, serialized),
                    )
                else:
                    result = conn.execute(
                        "UPDATE opsatlas.change_plans SET plan=%s::jsonb,plan_digest=%s "
                        "WHERE id=%s::uuid AND tenant_id=%s::uuid AND execution_permitted=false",
                        (serialized, digest, plan_id, tenant_id),
                    )
                    if result.rowcount != 1:
                        raise KeyError("persisted change workflow not found or execution-enabled")
                self._append_evidence_with_conn(
                    conn, tenant_id=tenant_id, event_type=event_type,
                    collector="local-control-plane-api/0.1", payload=event_payload,
                )

    def persisted_change_workflows(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            return conn.execute(
                "SELECT p.plan FROM opsatlas.change_plans p WHERE p.tenant_id=%s::uuid "
                "AND p.plan ? 'workflow' ORDER BY p.created_at,p.id",
                (tenant_id,),
            ).fetchall()

    def plans(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            return conn.execute(
                "SELECT p.id::text AS plan_id,p.request_id::text,p.plan,p.execution_permitted,p.created_at,r.action,COALESCE(a.external_id,'') AS target "
                "FROM opsatlas.change_plans p JOIN opsatlas.authorization_requests r ON r.tenant_id=p.tenant_id AND r.id=p.request_id "
                "LEFT JOIN opsatlas.assets a ON a.tenant_id=r.tenant_id AND a.id=r.target_asset_id "
                "WHERE p.tenant_id=%s::uuid ORDER BY p.created_at DESC,p.id DESC LIMIT 500",
                (tenant_id,),
            ).fetchall()

    def add_verified_approval(self, signed_record: dict[str, Any], verified: dict[str, Any]) -> None:
        approval = verified
        signature = signed_record["signature"]
        payload = json.dumps(approval, sort_keys=True, separators=(",", ":")).encode()
        signature_bytes = base64.b64decode(signature["signature_base64"], validate=True)
        tenant_id = str(approval["scope"]["tenant_id"])
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            conn.execute(
                "INSERT INTO opsatlas.approvals(id,tenant_id,request_id,plan_id,approver_identity_id,signature_algorithm,key_id,signature,signed_payload_digest,expires_at,verified_at) "
                "VALUES(%s::uuid,%s::uuid,%s::uuid,%s::uuid,(SELECT id FROM opsatlas.identities WHERE tenant_id=%s::uuid AND external_id=%s),%s,%s,%s,%s,%s::timestamptz,now())",
                (approval["approval_id"],tenant_id,approval["request_id"],approval["scope"]["plan_id"],tenant_id,approval["approver_id"],signature["algorithm"],signature["key_id"],signature_bytes,hashlib.sha256(payload).hexdigest(),approval["expires_at"]),
            )

    def approvals(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            return conn.execute(
                "SELECT a.id::text AS approval_id,a.request_id::text,a.plan_id::text,i.external_id AS approver_id,a.expires_at,a.revoked_at,a.signed_payload_digest "
                "FROM opsatlas.approvals a JOIN opsatlas.identities i ON i.tenant_id=a.tenant_id AND i.id=a.approver_identity_id "
                "WHERE a.tenant_id=%s::uuid ORDER BY a.created_at DESC,a.id DESC LIMIT 500",
                (tenant_id,),
            ).fetchall()

    def record_evidence(self, *, tenant_id: str, event_type: str, collector: str, payload: dict[str, Any], collected_at: str | None = None):
        with self.pool.connection() as conn:
            with conn.transaction():
                return self._append_evidence_with_conn(conn, tenant_id=tenant_id, event_type=event_type,
                    collector=collector, payload=payload, collected_at=collected_at)

    @staticmethod
    def _append_evidence_with_conn(conn: Any, *, tenant_id: str, event_type: str, collector: str,
                                   payload: dict[str, Any], collected_at: str | None = None):
        from .evidence import EvidenceEnvelope, EvidenceLedger

        envelope = EvidenceEnvelope(
            envelope_id=uuid4(), tenant_id=tenant_id, schema_version="evidence-envelope-v1",
            event_type=event_type, collected_at=collected_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            collector=collector, payload=payload,
        )
        EvidenceLedger._validate_envelope(envelope)
        conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
        tenant = conn.execute("SELECT id FROM opsatlas.tenants WHERE id=%s::uuid FOR UPDATE", (tenant_id,)).fetchone()
        if tenant is None:
            raise KeyError("tenant not found")
        previous = conn.execute(
            "SELECT payload FROM opsatlas.evidence_events WHERE tenant_id=%s::uuid AND payload ? 'record_version' ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        sequence = int(previous["payload"]["sequence"]) + 1 if previous else 1
        previous_hash = previous["payload"]["record_sha256"] if previous else None
        record = EvidenceLedger._build_record(envelope, sequence, previous_hash)
        serialized = record.as_dict()
        db_sequence = conn.execute(
            "SELECT COALESCE(max(sequence),0)+1 AS sequence FROM opsatlas.evidence_events WHERE tenant_id=%s::uuid",
            (tenant_id,),
        ).fetchone()["sequence"]
        conn.execute(
            "INSERT INTO opsatlas.evidence_events(tenant_id,sequence,event_id,occurred_at,event_type,actor_id,subject_type,subject_id,payload,previous_hash,event_hash) "
            "VALUES(%s::uuid,%s,%s::uuid,%s::timestamptz,%s,%s,%s,%s,%s::jsonb,%s,%s)",
            (tenant_id, db_sequence, str(record.record_id), record.appended_at, event_type, collector,
             str(payload.get("subject_type", "")) or None, str(payload.get("subject_id", "")) or None,
             json.dumps(serialized, sort_keys=True, separators=(",", ":")), previous_hash, record.record_sha256),
        )
        return record

    def evidence_records(self, tenant_id: str, event_type: str | None = None):
        from .evidence import EvidenceLedger

        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            if event_type is None:
                rows = conn.execute(
                    "SELECT payload FROM opsatlas.evidence_events WHERE tenant_id=%s::uuid AND payload ? 'record_version' ORDER BY sequence",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT payload FROM opsatlas.evidence_events WHERE tenant_id=%s::uuid AND event_type=%s AND payload ? 'record_version' ORDER BY sequence",
                    (tenant_id, event_type),
                ).fetchall()
        return tuple(EvidenceLedger.record_from_dict(row["payload"]) for row in rows)

    def verify_evidence(self, tenant_id: str) -> dict[str, Any]:
        from .evidence import EvidenceLedger

        records = list(self.evidence_records(tenant_id))
        return EvidenceLedger.verify_records(tenant_id, records)

    def graph_for_tenant(self, tenant_id: str) -> dict[str, list[dict[str, Any]]]:
        from .graph import GraphEdge, GraphNode

        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            assets = conn.execute(
                "SELECT external_id,asset_type,environment,lifecycle_state,manufacturer,model,attributes "
                "FROM opsatlas.assets WHERE tenant_id=%s::uuid ORDER BY external_id LIMIT 10001",
                (tenant_id,),
            ).fetchall()
            edge_rows = conn.execute(
                "SELECT e.id::text AS edge_id,s.external_id AS source_id,t.external_id AS target_id,e.relation,e.attributes "
                "FROM opsatlas.graph_edges e JOIN opsatlas.assets s ON s.tenant_id=e.tenant_id AND s.id=e.source_asset_id "
                "JOIN opsatlas.assets t ON t.tenant_id=e.tenant_id AND t.id=e.target_asset_id "
                "WHERE e.tenant_id=%s::uuid ORDER BY e.id LIMIT 20001",
                (tenant_id,),
            ).fetchall()
        if len(assets) > 10000 or len(edge_rows) > 20000:
            raise ValueError("graph exceeds local response cap; use paginated graph reads")
        nodes = [GraphNode(
            node_id=row["external_id"], tenant_id=tenant_id, kind=row["asset_type"],
            attributes={**row["attributes"], "environment": row["environment"], "lifecycle_state": row["lifecycle_state"],
                        "manufacturer": row["manufacturer"], "model": row["model"]},
        ).as_dict() for row in assets]
        edges = [GraphEdge(
            edge_id=UUID(row["edge_id"]), tenant_id=tenant_id,
            source_id=row["source_id"], target_id=row["target_id"], relation=row["relation"],
            attributes=row["attributes"],
        ).as_dict() for row in edge_rows]
        return {"nodes": nodes, "edges": edges}

    def add_graph_node(self, node: Any) -> dict[str, Any]:
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (node.tenant_id,))
                row = conn.execute(
                    "INSERT INTO opsatlas.assets(tenant_id,external_id,asset_type,environment,attributes) "
                    "VALUES(%s::uuid,%s,%s,%s,%s::jsonb) "
                    "ON CONFLICT(tenant_id,external_id) DO UPDATE SET asset_type=excluded.asset_type,environment=excluded.environment,attributes=excluded.attributes,observed_at=now() "
                    "RETURNING external_id,asset_type,environment,lifecycle_state,manufacturer,model",
                    (node.tenant_id,node.node_id,node.kind,str(node.attributes.get("environment", "lab")),
                     json.dumps(node.attributes, sort_keys=True, separators=(",", ":"))),
                ).fetchone()
                result = {"node_id": row["external_id"], "tenant_id": node.tenant_id, "kind": row["asset_type"],
                          "attributes": {**node.attributes, "environment": row["environment"], "lifecycle_state": row["lifecycle_state"],
                                         "manufacturer": row["manufacturer"], "model": row["model"]}}
                self._append_evidence_with_conn(conn, tenant_id=node.tenant_id, event_type="graph.node.added",
                    collector="local-control-plane-api/0.1", payload=result | {"tenant_id": node.tenant_id})
        return result

    def add_graph_edge(self, edge: Any) -> dict[str, Any]:
        if edge.source_id == edge.target_id:
            raise ValueError("self-referential graph edges are not accepted")
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (edge.tenant_id,))
                row = conn.execute(
                    "INSERT INTO opsatlas.graph_edges(id,tenant_id,source_asset_id,target_asset_id,relation,attributes) "
                    "SELECT %s::uuid,%s::uuid,s.id,t.id,%s,%s::jsonb FROM opsatlas.assets s CROSS JOIN opsatlas.assets t "
                    "WHERE s.tenant_id=%s::uuid AND t.tenant_id=%s::uuid AND s.external_id=%s AND t.external_id=%s "
                    "RETURNING id::text",
                    (str(edge.edge_id),edge.tenant_id,edge.relation,json.dumps(edge.attributes,sort_keys=True,separators=(",",":")),
                     edge.tenant_id,edge.tenant_id,edge.source_id,edge.target_id),
                ).fetchone()
                if row is None:
                    raise KeyError("graph edge endpoints must exist as assets in the same tenant")
                result = edge.as_dict()
                self._append_evidence_with_conn(conn, tenant_id=edge.tenant_id, event_type="graph.edge.added",
                    collector="local-control-plane-api/0.1", payload=result | {"tenant_id": edge.tenant_id})
        return result

    def integration_connections(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            return conn.execute(
                "SELECT c.id::text, c.name, c.protocol, c.vendor, c.product, c.base_url, c.credential_ref, "
                "c.allowed_hosts,c.access_mode,c.status,c.scopes,c.created_at,r.outcome AS last_outcome, "
                "r.http_status AS last_http_status,r.latency_ms AS last_latency_ms,r.finished_at AS last_probed_at "
                "FROM opsatlas.integration_connections c LEFT JOIN LATERAL (SELECT outcome,http_status,latency_ms,finished_at "
                "FROM opsatlas.integration_runs WHERE tenant_id=c.tenant_id AND connection_id=c.id "
                "AND COALESCE(diagnostics->>'synthetic','false') <> 'true' "
                "ORDER BY started_at DESC,id DESC LIMIT 1) r ON true "
                "WHERE c.tenant_id = %s::uuid ORDER BY c.name, c.id",
                (tenant_id,),
            ).fetchall()

    def integration_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            row = conn.execute(
                "SELECT id::text,name,protocol,vendor,product,base_url,credential_ref,allowed_hosts,access_mode,status,scopes,config->>'auth_scheme' AS auth_scheme "
                "FROM opsatlas.integration_connections WHERE tenant_id=%s::uuid AND id=%s::uuid",
                (tenant_id, connection_id),
            ).fetchone()
        if row is None:
            raise KeyError("integration connection not found for tenant")
        return row

    def record_integration_probe(self, *, tenant_id: str, connection_id: str,
                                 result: dict[str, Any] | None, error_code: str | None = None) -> dict[str, Any]:
        outcome = str(result.get("outcome", "healthy")) if result is not None else "failed"
        http_status = result.get("http_status") if result else None
        latency_ms = result.get("latency_ms") if result else None
        records_read = int(result.get("records_read", 0)) if result else 0
        diagnostics = result.get("diagnostics", {}) if result else {}
        event_type = "integration.probe.completed" if outcome == "healthy" else "integration.probe.partial" if outcome == "partial" else "integration.probe.failed"
        event_payload = {
            "tenant_id": tenant_id, "connection_id": connection_id, "outcome": outcome,
            "protocol": result.get("protocol") if result else None,
            "http_status": http_status, "latency_ms": latency_ms,
            "records_read": records_read, "error_code": error_code,
            "diagnostics": diagnostics, "read_only": True, "execution_permitted": False,
        }
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
                conn.execute("SELECT id FROM opsatlas.tenants WHERE id=%s::uuid FOR UPDATE", (tenant_id,))
                run = conn.execute(
                    "INSERT INTO opsatlas.integration_runs(tenant_id,connection_id,started_at,finished_at,outcome,http_status,latency_ms,records_read,error_code,diagnostics) "
                    "SELECT %s::uuid,c.id,now(),now(),%s,%s,%s,%s,%s,%s::jsonb FROM opsatlas.integration_connections c "
                    "WHERE c.tenant_id=%s::uuid AND c.id=%s::uuid RETURNING id::text,finished_at",
                    (tenant_id,outcome,http_status,latency_ms,records_read,error_code,
                     json.dumps(diagnostics,sort_keys=True,separators=(",",":")),tenant_id,connection_id),
                ).fetchone()
                if run is None:
                    raise KeyError("integration connection not found for tenant")
                conn.execute(
                    "UPDATE opsatlas.integration_connections SET status=%s,updated_at=now() WHERE tenant_id=%s::uuid AND id=%s::uuid",
                    ("healthy" if outcome == "healthy" else "degraded",tenant_id,connection_id),
                )
                self._append_evidence_with_conn(conn, tenant_id=tenant_id, event_type=event_type,
                    collector="local-control-plane-api/0.1", payload=event_payload)
        return {"run_id": run["id"], "outcome": outcome, "http_status": http_status,
                "latency_ms": latency_ms, "records_read": records_read,
                "error_code": error_code, "execution_permitted": False}

    def add_integration(self, tenant_id: str, item: dict[str, Any]) -> dict[str, Any]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            return conn.execute(
                "INSERT INTO opsatlas.integration_connections (tenant_id,name,protocol,vendor,product,base_url,credential_ref,access_mode,allowed_hosts,scopes,config) "
                "VALUES (%s::uuid,%s,%s,%s,%s,%s,%s,'read_only',%s,%s,%s::jsonb) "
                "RETURNING id::text,name,protocol,vendor,product,base_url,credential_ref,access_mode,status,scopes,created_at",
                (tenant_id,item["name"],item["protocol"],item.get("vendor"),item.get("product"),item.get("base_url"),item.get("credential_ref"),item["allowed_hosts"],item["scopes"],item["config_json"]),
            ).fetchone()

    def analytics_overview(self, tenant_id: str, include_synthetic_demo: bool = False) -> dict[str, Any]:
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            tenant_source = conn.execute(
                "SELECT COALESCE(metadata->>'synthetic','false')='true' AS synthetic FROM opsatlas.tenants WHERE id=%s::uuid",
                (tenant_id,),
            ).fetchone()
            if tenant_source and tenant_source["synthetic"] and not include_synthetic_demo:
                return {"tenant_id": tenant_id, "counts": {"assets": 0, "requests": 0, "connections": 0, "maintenance_open": 0},
                        "energy_24h": [], "kpis": [], "telemetry_freshness": {"readings_24h": 0, "latest_reading": None},
                        "source_status": "synthetic_demo_excluded", "synthetic_data_must_be_labeled": True,
                        "predictive_outputs_are_advisory": True, "execution_permitted": False}
            counts = conn.execute(
                "SELECT (SELECT count(*) FROM opsatlas.assets WHERE tenant_id=%s::uuid) AS assets, "
                "(SELECT count(*) FROM opsatlas.authorization_requests WHERE tenant_id=%s::uuid) AS requests, "
                "(SELECT count(*) FROM opsatlas.integration_connections WHERE tenant_id=%s::uuid) AS connections, "
                "(SELECT count(*) FROM opsatlas.maintenance_work_orders WHERE tenant_id=%s::uuid AND status IN ('recommended','open','in_progress')) AS maintenance_open",
                (tenant_id,tenant_id,tenant_id,tenant_id),
            ).fetchone()
            energy = conn.execute(
                "SELECT facility_id::text, count(*) AS samples, round(avg(power_kw),3) AS average_kw, "
                "round(max(power_kw),3) AS peak_kw, round(sum(energy_kwh),3) AS energy_kwh, "
                "max(observed_at) AS last_observed_at "
                "FROM opsatlas.energy_readings WHERE tenant_id=%s::uuid AND observed_at >= now()-interval '24 hours' "
                "GROUP BY facility_id ORDER BY facility_id",
                (tenant_id,),
            ).fetchall()
            kpis = conn.execute(
                "SELECT d.key,d.name,d.unit,o.value,o.status,o.window_end,o.sample_count,o.lineage "
                "FROM opsatlas.kpi_definitions d JOIN LATERAL (SELECT value,status,window_end,sample_count,lineage "
                "FROM opsatlas.kpi_observations WHERE tenant_id=d.tenant_id AND kpi_id=d.id "
                "ORDER BY window_end DESC LIMIT 1) o ON true WHERE d.tenant_id=%s::uuid AND d.enabled ORDER BY d.key",
                (tenant_id,),
            ).fetchall()
            freshness = conn.execute(
                "SELECT count(*) AS readings_24h,max(observed_at) AS latest_reading "
                "FROM opsatlas.sensor_readings WHERE tenant_id=%s::uuid AND observed_at >= now()-interval '24 hours'",
                (tenant_id,),
            ).fetchone()
        return {"tenant_id": tenant_id, "counts": counts, "energy_24h": energy, "kpis": kpis,
                "source_status": "synthetic_demo" if tenant_source and tenant_source["synthetic"] else "observed",
                "telemetry_freshness": freshness, "synthetic_data_must_be_labeled": True,
                "synthetic_demo_mode": bool(tenant_source and tenant_source["synthetic"] and include_synthetic_demo),
                "predictive_outputs_are_advisory": True, "execution_permitted": False}

    def lifecycle_cost_overview(self, tenant_id: str, include_synthetic_demo: bool = False) -> dict[str, Any]:
        """Read approved price lineage, lifecycle PV estimates and posted actuals."""
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            estimates = conn.execute(
                "SELECT e.id::text,e.scenario_key,e.name,e.lifecycle_phase,e.status,e.version,e.currency,e.geography,"
                "e.price_as_of,e.horizon_months,e.it_capacity_kw,e.facility_area_m2,e.rack_count,e.annual_energy_kwh,"
                "e.annual_useful_work,e.discount_rate,e.contingency_pct,e.assumptions,e.calculation_version,"
                "coalesce(r.lifecycle_pv,0) AS lifecycle_pv,coalesce(r.low_pv,0) AS low_pv,coalesce(r.high_pv,0) AS high_pv,"
                "coalesce(r.first_period_cost,0) AS first_period_cost,coalesce(r.line_count,0) AS line_count,"
                "coalesce(r.unpriced_lines,0) AS unpriced_lines,coalesce(r.synthetic_lines,0) AS synthetic_lines "
                "FROM opsatlas.estimate_scenarios e LEFT JOIN (SELECT tenant_id,estimate_id,currency,"
                "sum(present_value_base) AS lifecycle_pv,sum(present_value_low) AS low_pv,sum(present_value_high) AS high_pv,"
                "sum(first_period_cost) AS first_period_cost,sum(line_count) AS line_count,"
                "sum(unpriced_lines) AS unpriced_lines,sum(synthetic_lines) AS synthetic_lines "
                "FROM opsatlas.estimate_cost_rollup GROUP BY tenant_id,estimate_id,currency) r "
                "ON r.tenant_id=e.tenant_id AND r.estimate_id=e.id WHERE e.tenant_id=%s::uuid "
                "ORDER BY e.created_at DESC LIMIT 100", (tenant_id,),
            ).fetchall()
            prices = conn.execute(
                "SELECT p.item_code,p.description,p.category,p.manufacturer,p.model,p.classification_system,"
                "p.classification_code,p.quantity_unit,p.unit_price,p.currency,p.normalized_unit_price,cb.currency AS book_currency,"
                "p.currency_basis_date,p.fx_to_book,p.geography,p.delivery_basis,p.observed_at,p.valid_from,p.valid_to,"
                "p.source_kind,p.source_name,p.source_ref,p.confidence,"
                "p.quality_status,p.provenance FROM opsatlas.price_observations p "
                "JOIN opsatlas.cost_books cb ON cb.tenant_id=p.tenant_id AND cb.id=p.cost_book_id "
                "WHERE p.tenant_id=%s::uuid "
                "ORDER BY p.observed_at DESC LIMIT 500", (tenant_id,),
            ).fetchall()
            actuals = conn.execute(
                "SELECT accounting_period,cost_type,currency,sum(amount) AS actual_amount,count(*) AS entries,"
                "bool_or(provenance->>'synthetic'='true') AS synthetic "
                "FROM opsatlas.cost_actuals WHERE tenant_id=%s::uuid GROUP BY accounting_period,cost_type,currency "
                "ORDER BY accounting_period DESC,cost_type LIMIT 500", (tenant_id,),
            ).fetchall()
        synthetic_prices = (
            any(p.get("source_kind") == "synthetic_demo" or p.get("provenance", {}).get("synthetic") is True for p in prices)
            or any(int(e.get("synthetic_lines") or 0) > 0 for e in estimates)
            or any(a.get("synthetic") is True for a in actuals)
        )
        demo_tenant = any(
            tenant.get("tenant_id") == tenant_id and tenant.get("synthetic")
            for tenant in self.tenants()
        )
        show_synthetic = bool(include_synthetic_demo and demo_tenant)
        return {"tenant_id": tenant_id, "estimates": estimates if (not synthetic_prices or show_synthetic) else [],
                "prices": prices if (not synthetic_prices or show_synthetic) else [],
                "actuals": actuals if (not synthetic_prices or show_synthetic) else [],
                "synthetic": synthetic_prices,
                "synthetic_demo_mode": show_synthetic,
                "execution_permitted": False}

    def placement_snapshots(self, tenant_id: str) -> list[dict[str, Any]]:
        """List at most 100 tenant-scoped, immutable draft comparison snapshots."""
        with self.pool.connection() as conn:
            conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
            return conn.execute(
                "SELECT id::text AS scenario_id,name,schema_version,payload,payload_sha256,created_by,created_at "
                "FROM opsatlas.placement_comparison_snapshots WHERE tenant_id=%s::uuid "
                "ORDER BY created_at DESC,id DESC LIMIT 100", (tenant_id,),
            ).fetchall()

    def save_placement_snapshot(self, tenant_id: str, *, name: str, payload: str,
                                payload_sha256: str, schema_version: str) -> dict[str, Any]:
        """Persist one tenant-scoped draft snapshot; rows are append-only."""
        with self.pool.connection() as conn:
            with conn.transaction():
                conn.execute("SELECT set_config('opsatlas.tenant_id', %s, true)", (tenant_id,))
                return conn.execute(
                    "INSERT INTO opsatlas.placement_comparison_snapshots"
                    "(tenant_id,name,schema_version,payload,payload_sha256,created_by) "
                    "VALUES(%s::uuid,%s,%s,%s::jsonb,%s,NULL) "
                    "RETURNING id::text AS scenario_id,name,schema_version,payload,payload_sha256,created_at",
                    (tenant_id, name, schema_version, payload, payload_sha256),
                ).fetchone()
