-- Deterministic, visibly synthetic demo dataset. Never run against production.
BEGIN;
INSERT INTO opsatlas.tenants(id,slug,name,metadata) VALUES
 ('00000000-0000-4000-8000-000000000001','opsatlas-demo','OpsAtlas Synthetic Lab','{"synthetic":true}')
ON CONFLICT(id) DO NOTHING;
SELECT set_config('opsatlas.tenant_id','00000000-0000-4000-8000-000000000001',true);
INSERT INTO opsatlas.tenant_memberships(tenant_id,auth_user_id,role) VALUES
 ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000011','owner') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.sites(id,tenant_id,code,name,country_code,timezone,metadata) VALUES
 ('00000000-0000-4000-8000-000000000021','00000000-0000-4000-8000-000000000001','CAI-LAB','Cairo Synthetic Lab','EG','Africa/Cairo','{"synthetic":true}') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.facilities(id,tenant_id,site_id,code,name,facility_type,design_capacity_kw,metadata) VALUES
 ('00000000-0000-4000-8000-000000000031','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000021','DC-A','Demonstration Facility A','lab',120,'{"synthetic":true}') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.racks(id,tenant_id,facility_id,code,row_label,rack_units,power_capacity_kw,metadata) VALUES
 ('00000000-0000-4000-8000-000000000041','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000031','R01','A',42,15,'{"synthetic":true}') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.assets(id,tenant_id,rack_id,external_id,asset_type,manufacturer,model,environment,attributes) VALUES
 ('00000000-0000-4000-8000-000000000051','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000041','demo-compute-01','server','Synthetic Vendor','Compute X','lab','{"synthetic":true,"cpu_cores":32,"memory_gib":256}'),
 ('00000000-0000-4000-8000-000000000052','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000041','demo-pdu-01','pdu','Synthetic Vendor','PDU X','lab','{"synthetic":true}'),
 ('00000000-0000-4000-8000-000000000053','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000041','demo-sensor-01','temperature-sensor','Synthetic Vendor','Temp X','lab','{"synthetic":true}')
ON CONFLICT(tenant_id,external_id) DO NOTHING;
INSERT INTO opsatlas.asset_identifiers(tenant_id,asset_id,namespace,identifier) VALUES
 ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000051','demo','asset-compute-001') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.integration_connections(id,tenant_id,name,protocol,vendor,product,base_url,status,config) VALUES
 ('00000000-0000-4000-8000-000000000061','00000000-0000-4000-8000-000000000001','Synthetic Redfish source','redfish','Synthetic Vendor','BMC simulator','https://redfish.demo.invalid','draft','{"synthetic":true,"credential_ref":null}') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.integration_capabilities(tenant_id,connection_id,capability,direction,verified,contract_version) VALUES
 ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000061','inventory.read','read',false,'demo-v1') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.integration_runs(id,tenant_id,connection_id,outcome,records_read,diagnostics) VALUES
 ('00000000-0000-4000-8000-000000000071','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000061','partial',3,'{"synthetic":true,"not_a_live_probe":true}') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.identities(id,tenant_id,external_id,identity_type,provider,attributes) VALUES
 ('00000000-0000-4000-8000-000000000011','00000000-0000-4000-8000-000000000001','demo-operator','human','synthetic','{"synthetic":true}') ON CONFLICT(tenant_id,external_id) DO NOTHING;
INSERT INTO opsatlas.role_bindings(tenant_id,identity_id,role,scope_type,scope_id,valid_until,approved_by) VALUES
 ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000011','viewer','facility','00000000-0000-4000-8000-000000000031',now()+interval '1 day','demo-policy') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.privileged_sessions(id,tenant_id,identity_id,target_asset_id,reason,expires_at,outcome) VALUES
 ('00000000-0000-4000-8000-000000000081','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000011','00000000-0000-4000-8000-000000000051','Synthetic PAM timeline example',now()+interval '5 minutes','demo_closed') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.authorization_requests(id,tenant_id,actor_identity_id,target_asset_id,action,mode,environment,reason,capabilities,decision,decision_reasons,decided_at) VALUES
 ('00000000-0000-4000-8000-000000000091','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000011','00000000-0000-4000-8000-000000000051','inventory.observe','observe','lab','Synthetic read-only inventory demonstration',ARRAY['asset.inventory.read'],'allow','["synthetic_demo_policy"]',now()) ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.change_plans(id,tenant_id,request_id,plan_digest,plan) VALUES
 ('00000000-0000-4000-8000-0000000000a1','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000091','demo-not-a-signature','{"synthetic":true,"mode":"observe","steps":[]}') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.agents(id,tenant_id,name,agent_version,trust_state,manifest_digest,status,metadata) VALUES
 ('00000000-0000-4000-8000-0000000000b1','00000000-0000-4000-8000-000000000001','demo-observer','0.0-demo','unverified','synthetic-digest','inactive','{"synthetic":true}') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.model_endpoints(id,tenant_id,provider,endpoint_url,model_id,status,config) VALUES
 ('00000000-0000-4000-8000-0000000000c1','00000000-0000-4000-8000-000000000001','local-demo','https://models.demo.invalid/v1','demo-model','unverified','{"synthetic":true}') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.mcp_servers(id,tenant_id,name,endpoint_url,status,allowlisted,metadata) VALUES
 ('00000000-0000-4000-8000-0000000000d1','00000000-0000-4000-8000-000000000001','Synthetic MCP catalog','https://mcp.demo.invalid/mcp','unverified',false,'{"synthetic":true}') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.mcp_tools(tenant_id,server_id,tool_name,description,input_schema,risk_class,approved) VALUES
 ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-0000000000d1','inventory.preview','Synthetic preview only','{"type":"object"}','unknown',false) ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.graph_edges(tenant_id,source_asset_id,target_asset_id,relation,attributes) VALUES
 ('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000051','00000000-0000-4000-8000-000000000052','powered_by','{"synthetic":true}') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.sensor_definitions(id,tenant_id,asset_id,connection_id,metric_key,display_name,unit,metric_kind,expected_interval_seconds,metadata) VALUES
 ('00000000-0000-4000-8000-0000000000e1','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000053','00000000-0000-4000-8000-000000000061','inlet_temp_c','Inlet temperature','degC','gauge',300,'{"synthetic":true}'),
 ('00000000-0000-4000-8000-0000000000e2','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000052','00000000-0000-4000-8000-000000000061','power_kw','PDU power','kW','gauge',300,'{"synthetic":true}') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.sensor_readings(tenant_id,sensor_id,observed_at,value_numeric,quality,source_run_id,labels)
SELECT '00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-0000000000e1',ts,
  22.5 + sin(extract(epoch from ts)/2400.0)*2.4 + sin(extract(epoch from ts)/170.0)*0.3,
  'good','00000000-0000-4000-8000-000000000071','{"synthetic":true,"generator":"deterministic_sine_v1"}'
FROM generate_series(date_trunc('hour',now())-interval '7 days',date_trunc('hour',now()),interval '5 minutes') ts
ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.energy_readings(tenant_id,facility_id,observed_at,meter_id,power_kw,energy_kwh,power_factor,carbon_gco2_kwh,source_run_id)
SELECT '00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000031',ts,'meter-demo-01',
  18 + sin(extract(epoch from ts)/3600.0)*2,1.5,0.96,420,'00000000-0000-4000-8000-000000000071'
FROM generate_series(date_trunc('hour',now())-interval '30 days',date_trunc('hour',now()),interval '5 minutes') ts
ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.maintenance_rules(id,tenant_id,asset_type,metric_key,algorithm,parameters,severity) VALUES
 ('00000000-0000-4000-8000-0000000000f1','00000000-0000-4000-8000-000000000001','server','inlet_temp_c','rolling_zscore_v1','{"window":288,"warning_z":2.5,"critical_z":3.5,"synthetic":true}','warning') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.maintenance_work_orders(id,tenant_id,asset_id,rule_id,status,priority,predicted_failure_at,confidence,explanation) VALUES
 ('00000000-0000-4000-8000-000000000102','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000051','00000000-0000-4000-8000-0000000000f1','recommended','normal',now()+interval '45 days',0.62,'{"synthetic":true,"reason":"demonstration only; not an operational prediction"}') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.kpi_definitions(id,tenant_id,key,name,unit,formula_version,dimensions,target) VALUES
 ('00000000-0000-4000-8000-000000000103','00000000-0000-4000-8000-000000000001','energy.pue','Power usage effectiveness','ratio','pue_demo_v1',ARRAY['facility'],1.5),
 ('00000000-0000-4000-8000-000000000104','00000000-0000-4000-8000-000000000001','energy.kwh_per_compute_hour','Energy per compute-hour','kWh/h','demo_v1',ARRAY['facility'],null),
 ('00000000-0000-4000-8000-000000000105','00000000-0000-4000-8000-000000000001','fleet.inventory_freshness','Inventory freshness','percent','freshness_demo_v1',ARRAY['facility'],99) ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.kpi_observations(tenant_id,kpi_id,window_start,window_end,dimension_key,value,sample_count,status,lineage)
SELECT '00000000-0000-4000-8000-000000000001',kpi,now()-interval '24 hours',now(),'facility:DC-A',v,n,'valid','{"synthetic":true,"formula":"demo seed only"}'
FROM (VALUES ('00000000-0000-4000-8000-000000000103'::uuid,1.42::numeric,288::bigint),('00000000-0000-4000-8000-000000000104',2.1,288),('00000000-0000-4000-8000-000000000105',97.5,3)) x(kpi,v,n)
ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.forecast_runs(id,tenant_id,metric_key,algorithm,algorithm_version,training_start,training_end,horizon_seconds,metrics,input_digest,model_digest) VALUES
 ('00000000-0000-4000-8000-000000000106','00000000-0000-4000-8000-000000000001','inlet_temp_c','seasonal_baseline','demo-v1',now()-interval '7 days',now(),3600,'{"mae":0.8,"synthetic":true}','synthetic-input-digest','synthetic-model-digest') ON CONFLICT(id) DO NOTHING;
INSERT INTO opsatlas.forecast_points(tenant_id,run_id,target_at,prediction,lower_bound,upper_bound,anomaly_score,explanation)
SELECT '00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000106',ts,23.0,20.0,26.0,0.1,'{"synthetic":true}'
FROM generate_series(date_trunc('hour',now())+interval '1 hour',date_trunc('hour',now())+interval '24 hours',interval '1 hour') ts ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.evidence_events(tenant_id,sequence,event_type,actor_id,subject_type,subject_id,payload,previous_hash,event_hash) VALUES
 ('00000000-0000-4000-8000-000000000001',1,'demo.dataset.loaded','demo-seed','tenant','opsatlas-demo','{"synthetic":true,"note":"not signed production evidence"}',null,'synthetic-demo-hash-1') ON CONFLICT DO NOTHING;
INSERT INTO opsatlas.benchmark_runs(tenant_id,suite,scenario,target_rows,concurrency,started_at,finished_at,result,environment) VALUES
 ('00000000-0000-4000-8000-000000000001','seed-example','not-a-measured-run',0,1,now(),now(),'{"synthetic":true,"not_a_stress_result":true}','{"synthetic":true}') ON CONFLICT DO NOTHING;
COMMIT;
