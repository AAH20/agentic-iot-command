SELECT set_config('opsatlas.tenant_id', '00000000-0000-4000-8000-000000000001', true);
SELECT count(*), avg(value_numeric)
FROM opsatlas.sensor_readings
WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid
  AND observed_at >= now() - interval '1 day'
  AND quality = 'good';
SELECT date_trunc('hour', observed_at) AS hour, avg(power_kw), sum(energy_kwh)
FROM opsatlas.energy_readings
WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid
  AND facility_id = '00000000-0000-4000-8000-000000000031'::uuid
  AND observed_at >= now() - interval '7 days'
GROUP BY 1 ORDER BY 1 DESC LIMIT 24;
SELECT id, asset_type, lifecycle_state
FROM opsatlas.assets WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid
ORDER BY id LIMIT 50;
