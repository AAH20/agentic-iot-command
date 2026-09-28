-- OpsAtlas relational core: PostgreSQL 14+, Supabase-compatible SQL.
-- Apply to a newly-created database only. No secrets are stored in this schema.
BEGIN;
CREATE SCHEMA IF NOT EXISTS opsatlas;
SET search_path = opsatlas, public;

CREATE TABLE tenants (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), slug text NOT NULL UNIQUE, name text NOT NULL,
 status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','archived')),
 metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE TABLE tenant_memberships (
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, auth_user_id uuid NOT NULL,
 role text NOT NULL CHECK(role IN ('owner','operator','auditor','viewer')),
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,auth_user_id)
);
CREATE TABLE sites (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 code text NOT NULL, name text NOT NULL, country_code char(2), timezone text,
 latitude numeric(9,6), longitude numeric(9,6), metadata jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,id), UNIQUE(tenant_id,code)
);
CREATE TABLE facilities (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 site_id uuid NOT NULL, code text NOT NULL, name text NOT NULL,
 facility_type text NOT NULL CHECK(facility_type IN ('datacenter','office','edge','lab','other')),
 design_capacity_kw numeric(14,3), status text NOT NULL DEFAULT 'active', metadata jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,id), UNIQUE(tenant_id,code),
 FOREIGN KEY(tenant_id,site_id) REFERENCES sites(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE racks (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 facility_id uuid NOT NULL, code text NOT NULL, row_label text, rack_units smallint CHECK(rack_units > 0),
 power_capacity_kw numeric(12,3), metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,facility_id,code),
 FOREIGN KEY(tenant_id,facility_id) REFERENCES facilities(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE assets (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 parent_asset_id uuid, rack_id uuid, external_id text NOT NULL, asset_type text NOT NULL,
 manufacturer text, model text, serial_number text, environment text NOT NULL DEFAULT 'lab',
 lifecycle_state text NOT NULL DEFAULT 'active' CHECK(lifecycle_state IN ('active','maintenance','retired','unknown')),
 observed_at timestamptz, attributes jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,external_id),
 FOREIGN KEY(tenant_id,parent_asset_id) REFERENCES assets(tenant_id,id),
 FOREIGN KEY(tenant_id,rack_id) REFERENCES racks(tenant_id,id)
);
CREATE INDEX assets_tenant_type_state_idx ON assets(tenant_id,asset_type,lifecycle_state,id);
CREATE INDEX assets_parent_idx ON assets(tenant_id,parent_asset_id) WHERE parent_asset_id IS NOT NULL;
CREATE TABLE asset_identifiers (
 tenant_id uuid NOT NULL, asset_id uuid NOT NULL, namespace text NOT NULL, identifier text NOT NULL,
 source_connection_id uuid, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,namespace,identifier),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES assets(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX asset_identifiers_asset_idx ON asset_identifiers(tenant_id,asset_id);

CREATE TABLE integration_connections (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 name text NOT NULL, protocol text NOT NULL CHECK(protocol IN ('rest_openapi','mcp_http','redfish','snmp','modbus_tcp','bacnet_ip','opcua','mqtt','ssh_readonly','custom')),
 vendor text, product text, base_url text, credential_ref text, secret_provider text,
 access_mode text NOT NULL DEFAULT 'read_only' CHECK(access_mode IN ('read_only','plan_only','disabled')),
 status text NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','configured','healthy','degraded','disabled')),
 allowed_hosts text[] NOT NULL DEFAULT '{}', scopes text[] NOT NULL DEFAULT '{}', config jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,name)
);
CREATE TABLE integration_capabilities (
 tenant_id uuid NOT NULL, connection_id uuid NOT NULL, capability text NOT NULL,
 direction text NOT NULL CHECK(direction IN ('read','write','event')), verified boolean NOT NULL DEFAULT false,
 contract_version text, PRIMARY KEY(tenant_id,connection_id,capability),
 FOREIGN KEY(tenant_id,connection_id) REFERENCES integration_connections(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE integration_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, connection_id uuid NOT NULL,
 started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
 outcome text NOT NULL CHECK(outcome IN ('running','healthy','failed','partial')),
 http_status integer, latency_ms integer CHECK(latency_ms IS NULL OR latency_ms >= 0), records_read bigint NOT NULL DEFAULT 0,
 error_code text, diagnostics jsonb NOT NULL DEFAULT '{}', trace_id text, UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,connection_id) REFERENCES integration_connections(tenant_id,id)
);
CREATE INDEX integration_runs_recent_idx ON integration_runs(tenant_id,connection_id,started_at DESC);
ALTER TABLE asset_identifiers ADD CONSTRAINT asset_identifiers_source_connection_fk
 FOREIGN KEY(tenant_id,source_connection_id) REFERENCES integration_connections(tenant_id,id);

CREATE TABLE identities (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 external_id text NOT NULL, identity_type text NOT NULL CHECK(identity_type IN ('human','agent','service','device')),
 provider text, status text NOT NULL DEFAULT 'active', attributes jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,external_id)
);
CREATE TABLE role_bindings (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, identity_id uuid NOT NULL,
 role text NOT NULL, scope_type text NOT NULL, scope_id text NOT NULL, valid_from timestamptz NOT NULL DEFAULT now(),
 valid_until timestamptz, approved_by text, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,identity_id) REFERENCES identities(tenant_id,id) ON DELETE CASCADE,
 CHECK(valid_until IS NULL OR valid_until > valid_from)
);
CREATE INDEX role_bindings_scope_idx ON role_bindings(tenant_id,scope_type,scope_id,valid_until);
CREATE TABLE privileged_sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, identity_id uuid NOT NULL,
 target_asset_id uuid, reason text NOT NULL, approval_id uuid, opened_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL, closed_at timestamptz, outcome text NOT NULL DEFAULT 'requested',
 FOREIGN KEY(tenant_id,identity_id) REFERENCES identities(tenant_id,id),
 FOREIGN KEY(tenant_id,target_asset_id) REFERENCES assets(tenant_id,id), CHECK(expires_at > opened_at)
);
CREATE INDEX privileged_sessions_identity_time_idx ON privileged_sessions(tenant_id,identity_id,opened_at DESC);
CREATE INDEX privileged_sessions_target_idx ON privileged_sessions(tenant_id,target_asset_id) WHERE target_asset_id IS NOT NULL;
CREATE TABLE authorization_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, actor_identity_id uuid NOT NULL,
 target_asset_id uuid, action text NOT NULL, mode text NOT NULL CHECK(mode IN ('observe','plan','mutate')),
 environment text NOT NULL, reason text NOT NULL, capabilities text[] NOT NULL DEFAULT '{}',
 decision text NOT NULL DEFAULT 'pending', decision_reasons jsonb NOT NULL DEFAULT '[]',
 created_at timestamptz NOT NULL DEFAULT now(), decided_at timestamptz, UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,actor_identity_id) REFERENCES identities(tenant_id,id),
 FOREIGN KEY(tenant_id,target_asset_id) REFERENCES assets(tenant_id,id)
);
CREATE INDEX authorization_requests_queue_idx ON authorization_requests(tenant_id,decision,created_at DESC,id);
CREATE INDEX authorization_requests_actor_idx ON authorization_requests(tenant_id,actor_identity_id,created_at DESC);
CREATE INDEX authorization_requests_target_idx ON authorization_requests(tenant_id,target_asset_id,created_at DESC) WHERE target_asset_id IS NOT NULL;
CREATE TABLE change_plans (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, request_id uuid NOT NULL,
 plan_version integer NOT NULL DEFAULT 1, plan_digest text NOT NULL, plan jsonb NOT NULL,
 execution_permitted boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,request_id,plan_version),
 FOREIGN KEY(tenant_id,request_id) REFERENCES authorization_requests(tenant_id,id)
);
CREATE TABLE approvals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, request_id uuid NOT NULL, plan_id uuid,
 approver_identity_id uuid NOT NULL, signature_algorithm text NOT NULL, key_id text NOT NULL, signature bytea NOT NULL,
 signed_payload_digest text NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz,
 verified_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,request_id) REFERENCES authorization_requests(tenant_id,id),
 FOREIGN KEY(tenant_id,plan_id) REFERENCES change_plans(tenant_id,id),
 FOREIGN KEY(tenant_id,approver_identity_id) REFERENCES identities(tenant_id,id)
);
CREATE INDEX approvals_active_idx ON approvals(tenant_id,expires_at) WHERE revoked_at IS NULL;
CREATE INDEX approvals_approver_idx ON approvals(tenant_id,approver_identity_id,created_at DESC);
ALTER TABLE privileged_sessions ADD CONSTRAINT privileged_sessions_approval_fk
 FOREIGN KEY(tenant_id,approval_id) REFERENCES approvals(tenant_id,id);

CREATE TABLE agents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, name text NOT NULL, agent_version text,
 trust_state text NOT NULL DEFAULT 'unverified', manifest_digest text, policy_profile text,
 status text NOT NULL DEFAULT 'inactive', metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,name), FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE TABLE model_endpoints (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, provider text NOT NULL,
 endpoint_url text NOT NULL, credential_ref text, model_id text, purpose text NOT NULL DEFAULT 'inference',
 status text NOT NULL DEFAULT 'unverified', config jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id), FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE TABLE mcp_servers (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, name text NOT NULL,
 endpoint_url text NOT NULL, credential_ref text, protocol_version text, status text NOT NULL DEFAULT 'unverified',
 allowlisted boolean NOT NULL DEFAULT false, last_discovered_at timestamptz, metadata jsonb NOT NULL DEFAULT '{}',
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,name), FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE TABLE mcp_tools (
 tenant_id uuid NOT NULL, server_id uuid NOT NULL, tool_name text NOT NULL, description text,
 input_schema jsonb NOT NULL DEFAULT '{}', risk_class text NOT NULL DEFAULT 'unknown', approved boolean NOT NULL DEFAULT false,
 discovered_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,server_id,tool_name),
 FOREIGN KEY(tenant_id,server_id) REFERENCES mcp_servers(tenant_id,id) ON DELETE CASCADE
);

CREATE TABLE graph_edges (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, source_asset_id uuid NOT NULL,
 target_asset_id uuid NOT NULL, relation text NOT NULL, attributes jsonb NOT NULL DEFAULT '{}',
 observed_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,source_asset_id) REFERENCES assets(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,target_asset_id) REFERENCES assets(tenant_id,id) ON DELETE CASCADE,
 CHECK(source_asset_id <> target_asset_id)
);
CREATE INDEX graph_edges_out_idx ON graph_edges(tenant_id,source_asset_id,relation,target_asset_id);
CREATE INDEX graph_edges_in_idx ON graph_edges(tenant_id,target_asset_id,relation,source_asset_id);
CREATE TABLE sensor_definitions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, asset_id uuid,
 connection_id uuid, metric_key text NOT NULL, display_name text NOT NULL, unit text NOT NULL,
 metric_kind text NOT NULL CHECK(metric_kind IN ('gauge','counter','state','event')), expected_interval_seconds integer,
 metadata jsonb NOT NULL DEFAULT '{}', UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES assets(tenant_id,id),
 FOREIGN KEY(tenant_id,connection_id) REFERENCES integration_connections(tenant_id,id)
);
CREATE TABLE sensor_readings (
 tenant_id uuid NOT NULL, sensor_id uuid NOT NULL, observed_at timestamptz NOT NULL,
 value_numeric numeric, value_text text, quality text NOT NULL DEFAULT 'good' CHECK(quality IN ('good','stale','estimated','invalid')),
 source_run_id uuid, ingested_at timestamptz NOT NULL DEFAULT now(), labels jsonb NOT NULL DEFAULT '{}',
 PRIMARY KEY(tenant_id,sensor_id,observed_at),
 FOREIGN KEY(tenant_id,sensor_id) REFERENCES sensor_definitions(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,source_run_id) REFERENCES integration_runs(tenant_id,id),
 CHECK(num_nonnulls(value_numeric,value_text)=1)
);
CREATE INDEX sensor_readings_time_idx ON sensor_readings(tenant_id,observed_at DESC,sensor_id);
CREATE INDEX sensor_readings_brin_idx ON sensor_readings USING brin(observed_at);
CREATE TABLE energy_readings (
 tenant_id uuid NOT NULL, facility_id uuid NOT NULL, observed_at timestamptz NOT NULL, meter_id text NOT NULL,
 power_kw numeric(14,4), energy_kwh numeric(18,6), voltage_v numeric(12,4), current_a numeric(12,4),
 power_factor numeric(6,5), carbon_gco2_kwh numeric(12,4), quality text NOT NULL DEFAULT 'good',
 source_run_id uuid, ingested_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,facility_id,meter_id,observed_at),
 FOREIGN KEY(tenant_id,facility_id) REFERENCES facilities(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,source_run_id) REFERENCES integration_runs(tenant_id,id),
 CHECK(power_kw IS NULL OR power_kw >= 0), CHECK(energy_kwh IS NULL OR energy_kwh >= 0)
);
CREATE INDEX energy_readings_time_idx ON energy_readings(tenant_id,facility_id,observed_at DESC);
CREATE INDEX energy_readings_brin_idx ON energy_readings USING brin(observed_at);

CREATE TABLE maintenance_rules (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, asset_type text NOT NULL,
 metric_key text NOT NULL, rule_version integer NOT NULL DEFAULT 1, algorithm text NOT NULL,
 parameters jsonb NOT NULL, severity text NOT NULL CHECK(severity IN ('info','warning','critical')),
 enabled boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE TABLE maintenance_work_orders (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, asset_id uuid NOT NULL, rule_id uuid,
 status text NOT NULL DEFAULT 'recommended', priority text NOT NULL DEFAULT 'normal', predicted_failure_at timestamptz,
 confidence numeric(5,4), explanation jsonb NOT NULL DEFAULT '{}', opened_at timestamptz NOT NULL DEFAULT now(), closed_at timestamptz,
 UNIQUE(tenant_id,id), FOREIGN KEY(tenant_id,asset_id) REFERENCES assets(tenant_id,id),
 FOREIGN KEY(tenant_id,rule_id) REFERENCES maintenance_rules(tenant_id,id), CHECK(confidence IS NULL OR confidence BETWEEN 0 AND 1)
);
CREATE INDEX maintenance_queue_idx ON maintenance_work_orders(tenant_id,status,priority,opened_at DESC);
CREATE TABLE kpi_definitions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, key text NOT NULL, name text NOT NULL,
 unit text NOT NULL, formula_version text NOT NULL, dimensions text[] NOT NULL DEFAULT '{}', target numeric,
 enabled boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,key), FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE TABLE kpi_observations (
 tenant_id uuid NOT NULL, kpi_id uuid NOT NULL, window_start timestamptz NOT NULL, window_end timestamptz NOT NULL,
 dimension_key text NOT NULL DEFAULT '', value numeric, sample_count bigint NOT NULL DEFAULT 0,
 status text NOT NULL DEFAULT 'valid' CHECK(status IN ('valid','partial','stale','invalid')),
 lineage jsonb NOT NULL DEFAULT '{}', calculated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,kpi_id,window_start,dimension_key),
 FOREIGN KEY(tenant_id,kpi_id) REFERENCES kpi_definitions(tenant_id,id) ON DELETE CASCADE,
 CHECK(window_end > window_start), CHECK(sample_count >= 0)
);
CREATE INDEX kpi_observations_recent_idx ON kpi_observations(tenant_id,kpi_id,window_end DESC);
CREATE TABLE forecast_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, metric_key text NOT NULL,
 algorithm text NOT NULL, algorithm_version text NOT NULL, training_start timestamptz NOT NULL, training_end timestamptz NOT NULL,
 generated_at timestamptz NOT NULL DEFAULT now(), horizon_seconds integer NOT NULL CHECK(horizon_seconds > 0),
 metrics jsonb NOT NULL, input_digest text NOT NULL, model_digest text, run_status text NOT NULL DEFAULT 'completed',
 UNIQUE(tenant_id,id), FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE, CHECK(training_end > training_start)
);
CREATE TABLE forecast_points (
 tenant_id uuid NOT NULL, run_id uuid NOT NULL, target_at timestamptz NOT NULL, prediction numeric NOT NULL,
 lower_bound numeric, upper_bound numeric, anomaly_score numeric, explanation jsonb NOT NULL DEFAULT '{}',
 PRIMARY KEY(tenant_id,run_id,target_at), FOREIGN KEY(tenant_id,run_id) REFERENCES forecast_runs(tenant_id,id) ON DELETE CASCADE,
 CHECK(lower_bound IS NULL OR upper_bound IS NULL OR lower_bound <= upper_bound)
);
CREATE TABLE evidence_events (
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, sequence bigint NOT NULL,
 event_id uuid NOT NULL DEFAULT gen_random_uuid(), occurred_at timestamptz NOT NULL DEFAULT now(),
 event_type text NOT NULL, actor_id text, subject_type text, subject_id text, payload jsonb NOT NULL,
 previous_hash text, event_hash text NOT NULL, PRIMARY KEY(tenant_id,sequence), UNIQUE(tenant_id,event_id)
);
CREATE INDEX evidence_subject_idx ON evidence_events(tenant_id,subject_type,subject_id,sequence DESC);
CREATE TABLE benchmark_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 suite text NOT NULL, scenario text NOT NULL, target_rows bigint NOT NULL, concurrency integer NOT NULL,
 started_at timestamptz NOT NULL, finished_at timestamptz, result jsonb NOT NULL DEFAULT '{}', environment jsonb NOT NULL DEFAULT '{}',
 CHECK(target_rows >= 0), CHECK(concurrency > 0)
);

-- Defense in depth: absent tenant scope returns no data. Backend sets it locally per transaction.
-- Draft comparison snapshots remain separate from approved cost books/estimates.
CREATE TABLE opsatlas.placement_comparison_snapshots (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL,
 name text NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 120),
 schema_version text NOT NULL CHECK(schema_version='placement-tco-comparison.v1'),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 payload_sha256 char(64) NOT NULL CHECK(payload_sha256 ~ '^[0-9a-f]{64}$'),
 created_by text,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id),FOREIGN KEY(tenant_id) REFERENCES opsatlas.tenants(id) ON DELETE CASCADE
);
CREATE INDEX placement_snapshots_recent_idx
 ON opsatlas.placement_comparison_snapshots(tenant_id,created_at DESC,id DESC);
CREATE OR REPLACE FUNCTION opsatlas.reject_placement_snapshot_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'placement comparison snapshots are immutable'; END $$;
CREATE TRIGGER placement_snapshots_immutable BEFORE UPDATE OR DELETE
 ON opsatlas.placement_comparison_snapshots FOR EACH ROW EXECUTE FUNCTION opsatlas.reject_placement_snapshot_mutation();

DO $$ DECLARE t record; BEGIN
 FOR t IN SELECT c.table_name FROM information_schema.columns c
  JOIN information_schema.tables b ON b.table_schema=c.table_schema AND b.table_name=c.table_name
  WHERE c.table_schema='opsatlas' AND c.column_name='tenant_id' AND b.table_type='BASE TABLE' LOOP
  EXECUTE format('ALTER TABLE opsatlas.%I ENABLE ROW LEVEL SECURITY',t.table_name);
  EXECUTE format('ALTER TABLE opsatlas.%I FORCE ROW LEVEL SECURITY',t.table_name);
  EXECUTE format('CREATE POLICY tenant_scope ON opsatlas.%I USING (tenant_id = nullif(current_setting(''opsatlas.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''opsatlas.tenant_id'',true),'''')::uuid)',t.table_name);
 END LOOP;
END $$;
REVOKE ALL ON SCHEMA opsatlas FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA opsatlas FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA opsatlas FROM PUBLIC;
COMMIT;
