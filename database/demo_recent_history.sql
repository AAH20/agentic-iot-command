-- Synthetic-only recency extension for the named opsatlas-demo tenant.
-- Adds a rolling 24-hour, 5-minute series; no connector is contacted.
BEGIN;
WITH ticks AS (
  SELECT n,
         date_trunc('minute',now())
           - (extract(epoch FROM date_trunc('minute',now()))::bigint % 300) * interval '1 second'
           - n * interval '5 minutes' AS ts
  FROM generate_series(0,288) AS n
)
INSERT INTO opsatlas.sensor_readings(tenant_id,sensor_id,observed_at,value_numeric,quality,source_run_id,labels)
SELECT '00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-0000000000e1',ts,
       22.5 + sin(extract(epoch FROM ts)/2400.0)*2.4 + sin(extract(epoch FROM ts)/170.0)*0.3,
       'estimated','00000000-0000-4000-8000-000000000071',
       '{"synthetic":true,"label":"NOT LIVE","generator":"demo_recent_series_v1"}'
FROM ticks ON CONFLICT DO NOTHING;

WITH ticks AS (
  SELECT n,
         date_trunc('minute',now())
           - (extract(epoch FROM date_trunc('minute',now()))::bigint % 300) * interval '1 second'
           - n * interval '5 minutes' AS ts
  FROM generate_series(0,288) AS n
)
INSERT INTO opsatlas.energy_readings(tenant_id,facility_id,observed_at,meter_id,power_kw,energy_kwh,power_factor,carbon_gco2_kwh,source_run_id)
SELECT '00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000031',ts,'meter-demo-01',
       18 + sin(extract(epoch FROM ts)/3600.0)*2,1.5,0.96,420,
       '00000000-0000-4000-8000-000000000071'
FROM ticks ON CONFLICT DO NOTHING;
COMMIT;
