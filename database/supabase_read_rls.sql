-- Optional Supabase overlay. Run after schema.sql in Supabase SQL editor/CLI.
-- Add opsatlas to the project's exposed schemas explicitly; do not grant anon access.
-- This overlay intentionally grants SELECT only. Mutations should pass through
-- the trusted API and its signed governance workflow, never the browser Data API.
BEGIN;
GRANT USAGE ON SCHEMA opsatlas TO authenticated;
GRANT SELECT ON ALL TABLES IN SCHEMA opsatlas TO authenticated;
DO $$ DECLARE t record; BEGIN
  -- Membership rows are self-readable; tenant IDs cannot be enumerated anonymously.
  DROP POLICY IF EXISTS tenant_scope ON opsatlas.tenant_memberships;
  DROP POLICY IF EXISTS member_self_read ON opsatlas.tenant_memberships;
  CREATE POLICY member_self_read ON opsatlas.tenant_memberships FOR SELECT TO authenticated
    USING (auth_user_id = (select auth.uid()));
  -- Replace local-service context policies with database-enforced Auth membership checks.
  FOR t IN SELECT table_name FROM information_schema.columns
    WHERE table_schema='opsatlas' AND column_name='tenant_id' AND table_name <> 'tenant_memberships'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_scope ON opsatlas.%I',t.table_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_member_read ON opsatlas.%I',t.table_name);
    EXECUTE format('CREATE POLICY tenant_member_read ON opsatlas.%I FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM opsatlas.tenant_memberships m WHERE m.tenant_id = opsatlas.%I.tenant_id AND m.auth_user_id = (select auth.uid())))',t.table_name,t.table_name);
  END LOOP;
END $$;
DROP POLICY IF EXISTS tenant_scope ON opsatlas.tenants;
CREATE POLICY tenant_member_read ON opsatlas.tenants FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM opsatlas.tenant_memberships m WHERE m.tenant_id=tenants.id AND m.auth_user_id=(select auth.uid())));
REVOKE ALL ON SCHEMA opsatlas FROM anon;
REVOKE ALL ON ALL TABLES IN SCHEMA opsatlas FROM anon;
COMMIT;
