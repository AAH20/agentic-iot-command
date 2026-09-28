-- Draft-only placement comparison snapshots. These are not approved estimates
-- or cost-book records; clients must retain the evidence boundary in payload.
BEGIN;
CREATE TABLE IF NOT EXISTS opsatlas.placement_comparison_snapshots (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 name text NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 120),
 schema_version text NOT NULL CHECK (schema_version='placement-tco-comparison.v1'),
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
 payload_sha256 char(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
 created_by text,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (tenant_id,id),
 FOREIGN KEY (tenant_id) REFERENCES opsatlas.tenants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS placement_snapshots_recent_idx
 ON opsatlas.placement_comparison_snapshots (tenant_id,created_at DESC,id DESC);
CREATE OR REPLACE FUNCTION opsatlas.reject_placement_snapshot_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'placement comparison snapshots are immutable'; END $$;
DROP TRIGGER IF EXISTS placement_snapshots_immutable ON opsatlas.placement_comparison_snapshots;
CREATE TRIGGER placement_snapshots_immutable BEFORE UPDATE OR DELETE
 ON opsatlas.placement_comparison_snapshots FOR EACH ROW EXECUTE FUNCTION opsatlas.reject_placement_snapshot_mutation();
ALTER TABLE opsatlas.placement_comparison_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE opsatlas.placement_comparison_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON opsatlas.placement_comparison_snapshots;
CREATE POLICY tenant_scope ON opsatlas.placement_comparison_snapshots
 USING (tenant_id=nullif(current_setting('opsatlas.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=nullif(current_setting('opsatlas.tenant_id',true),'')::uuid);
REVOKE ALL ON opsatlas.placement_comparison_snapshots FROM PUBLIC;
COMMIT;
