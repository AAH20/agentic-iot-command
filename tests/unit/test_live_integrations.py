import unittest
from unittest.mock import patch

from control_plane_core.api import LocalControlPlaneApi
from control_plane_core.live_integrations import LiveIntegrations


class LiveIntegrationTests(unittest.TestCase):
    def test_status_reports_configuration_without_returning_secrets(self) -> None:
        integrations = LiveIntegrations({
            "A2Z_OPENROUTER_API_KEY": "secret-value",
            "A2Z_VLLM_BASE_URL": "http://127.0.0.1:8000",
            "A2Z_MCP_SERVERS_JSON": "[]",
        })
        status = integrations.status()
        self.assertTrue(status["providers"][0]["configured"])
        self.assertTrue(status["providers"][1]["configured"])
        self.assertNotIn("secret-value", repr(status))
        self.assertFalse(status["tool_execution"])

    def test_openrouter_models_are_fetched_from_fixed_provider_endpoint(self) -> None:
        integrations = LiveIntegrations({"A2Z_OPENROUTER_API_KEY": "secret"})
        with patch("control_plane_core.live_integrations._request", return_value=({"data": [{"id": "vendor/model", "name": "Model"}]}, {})) as request:
            result = integrations.models("openrouter")
        self.assertEqual(result["models"], [{"id": "vendor/model", "name": "Model"}])
        self.assertEqual(request.call_args.args[0], "https://openrouter.ai/api/v1/models")
        self.assertEqual(request.call_args.kwargs["token"], "secret")

    def test_azure_retail_lookup_is_fixed_read_only_and_labels_list_price_basis(self) -> None:
        integrations = LiveIntegrations({})
        payload = {"Items": [{"serviceName": "Virtual Machines", "armRegionName": "eastus",
            "armSkuName": "Standard_D2s_v5", "retailPrice": 0.096, "currencyCode": "USD",
            "unitOfMeasure": "1 Hour", "priceType": "Consumption"}]}
        with patch("control_plane_core.live_integrations._request", return_value=(payload, {})) as request:
            result = integrations.azure_retail_prices(service_name="Virtual Machines", region="eastus", sku="Standard_D2s_v5")
        self.assertTrue(request.call_args.args[0].startswith("https://prices.azure.com/api/retail/prices?"))
        self.assertEqual(result["prices"][0]["retailPrice"], "0.096")
        self.assertFalse(result["persisted"])
        self.assertFalse(result["execution_permitted"])
        self.assertIn("Public retail list rates only", result["commercial_basis"])

    def test_azure_retail_lookup_rejects_filter_injection_before_network(self) -> None:
        integrations = LiveIntegrations({})
        with patch("control_plane_core.live_integrations._request") as request:
            with self.assertRaises(ValueError):
                integrations.azure_retail_prices(service_name="Virtual Machines' or name eq 'x")
        request.assert_not_called()

    def test_google_public_catalog_normalizes_money_and_excludes_tiered_rates(self) -> None:
        integrations = LiveIntegrations({"GOOGLE_CLOUD_BILLING_API_KEY": "secret-google-key"})
        services = {"services": [{"displayName": "Compute Engine", "serviceId": "6F81-5844-456A"}]}
        skus = {"skus": [
            {"skuId": "SKU-1", "description": "N2 Instance Core running", "serviceRegions": ["us-central1"], "category": {"usageType": "OnDemand"}, "pricingInfo": [{"effectiveTime": "2026-09-01T00:00:00Z", "pricingExpression": {"usageUnitDescription": "hour", "tieredRates": [{"startUsageAmount": 0, "unitPrice": {"units": "0", "nanos": 96000000}}]}}]},
            {"skuId": "SKU-2", "description": "N2 Instance Core tiers", "serviceRegions": ["us-central1"], "pricingInfo": [{"pricingExpression": {"tieredRates": [{"startUsageAmount": 0, "unitPrice": {"units": "0", "nanos": 0}}, {"startUsageAmount": 100, "unitPrice": {"units": "1", "nanos": 0}}]}}]},
        ], "nextPageToken": "more"}
        with patch("control_plane_core.live_integrations._request", side_effect=[(services, {}), (skus, {})]) as request:
            result = integrations.google_cloud_retail_prices(service_name="Compute Engine", region="us-central1", sku_query="N2 Instance Core")
        self.assertEqual(request.call_count, 2)
        self.assertTrue(all(call.args[0].startswith("https://cloudbilling.googleapis.com/v1/") for call in request.call_args_list))
        self.assertEqual(result["prices"][0]["retailPrice"], "0.096")
        self.assertTrue(result["prices"][0]["estimate_eligible"])
        self.assertFalse(result["prices"][1]["estimate_eligible"])
        self.assertTrue(result["truncated"])
        self.assertNotIn("secret-google-key", repr(result))

    def test_google_catalog_requires_server_side_key_before_network(self) -> None:
        integrations = LiveIntegrations({})
        with patch("control_plane_core.live_integrations._request") as request:
            with self.assertRaisesRegex(ConnectionError, "GOOGLE_CLOUD_BILLING_API_KEY"):
                integrations.google_cloud_retail_prices(service_name="Compute Engine", region="us-central1", sku_query="N2")
        request.assert_not_called()

    def test_vllm_rejects_non_loopback_plain_http_before_network(self) -> None:
        integrations = LiveIntegrations({"A2Z_VLLM_BASE_URL": "http://example.com:8000"})
        with patch("control_plane_core.live_integrations._request") as request:
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                integrations.models("vllm")
        request.assert_not_called()

    def test_redfish_adapter_reads_service_root_with_admin_and_connector_host_pins(self) -> None:
        integrations = LiveIntegrations({
            "A2Z_INTEGRATION_ALLOWED_HOSTS": "bmc.example.test",
            "REDFISH_TOKEN": "never-return-this-token",
        })
        connector = {
            "protocol": "redfish", "base_url": "https://bmc.example.test",
            "allowed_hosts": ["bmc.example.test"], "credential_ref": "REDFISH_TOKEN",
        }
        root = {"@odata.id": "/redfish/v1/", "Name": "BMC", "RedfishVersion": "1.20.0", "Systems": {"@odata.id": "/redfish/v1/Systems"}}
        with patch("control_plane_core.live_integrations._request", side_effect=[
            (root, {"opsatlas-http-status": "200", "opsatlas-content-type": "application/json"}),
            ({"Members": [{"@odata.id": "/redfish/v1/Systems/1"}]}, {}),
        ]) as request:
            result = integrations.probe_connection(connector)
        self.assertEqual(request.call_args_list[0].args[0], "https://bmc.example.test/redfish/v1/")
        self.assertEqual(request.call_args_list[0].kwargs["token"], "never-return-this-token")
        self.assertEqual(result["outcome"], "healthy")
        self.assertEqual(result["diagnostics"]["redfish_version"], "1.20.0")
        self.assertEqual(result["diagnostics"]["collections"]["Systems"]["member_count"], 1)
        self.assertNotIn("never-return-this-token", repr(result))
        self.assertFalse(result["execution_permitted"])

    def test_redfish_basic_secret_is_sent_only_as_header_and_never_returned(self) -> None:
        integrations = LiveIntegrations({"BMC_BASIC": "operator:secret-password"})
        connector = {
            "protocol": "redfish", "base_url": "http://127.0.0.1:8000/redfish/v1/",
            "allowed_hosts": ["127.0.0.1"], "credential_ref": "BMC_BASIC", "auth_scheme": "http_basic",
        }
        root = {"@odata.id": "/redfish/v1/", "Name": "Test BMC", "RedfishVersion": "1.20.0"}
        with patch("control_plane_core.live_integrations._request", return_value=(root, {
            "opsatlas-http-status": "200", "opsatlas-content-type": "application/json",
        })) as request:
            result = integrations.probe_connection(connector)
        self.assertEqual(request.call_args.kwargs["token"], "")
        self.assertEqual(request.call_args.kwargs["extra_headers"]["Authorization"], "Basic b3BlcmF0b3I6c2VjcmV0LXBhc3N3b3Jk")
        self.assertNotIn("secret-password", repr(result))

    def test_rest_openapi_adapter_reads_only_and_summarizes_contract(self) -> None:
        integrations = LiveIntegrations({})
        connector = {
            "protocol": "rest_openapi", "base_url": "http://127.0.0.1:8080/openapi.json",
            "allowed_hosts": ["127.0.0.1"], "credential_ref": None,
        }
        document = {"openapi": "3.1.0", "info": {"title": "Lab API", "version": "1"}, "paths": {"/health": {}, "/inventory": {}}}
        with patch("control_plane_core.live_integrations._request", return_value=(document, {
            "opsatlas-http-status": "200", "opsatlas-content-type": "application/json",
        })) as request:
            result = integrations.probe_connection(connector)
        request.assert_called_once()
        self.assertEqual(request.call_args.args[0], connector["base_url"])
        self.assertEqual(result["diagnostics"]["document_type"], "openapi")
        self.assertEqual(result["diagnostics"]["path_count"], 2)

    def test_saved_host_is_not_enough_without_operator_allowlist_and_unsupported_protocol_never_connects(self) -> None:
        connector = {"protocol": "redfish", "base_url": "https://bmc.example.test", "allowed_hosts": ["bmc.example.test"]}
        integrations = LiveIntegrations({})
        with patch("control_plane_core.live_integrations._request") as request:
            with self.assertRaisesRegex(PermissionError, "A2Z_INTEGRATION_ALLOWED_HOSTS"):
                integrations.probe_connection(connector)
            with self.assertRaisesRegex(ValueError, "no live adapter"):
                integrations.probe_connection({**connector, "protocol": "modbus_tcp", "base_url": "modbus+tcp://bmc.example.test:502"})
            with self.assertRaisesRegex(PermissionError, "A2Z_INTEGRATION_ALLOWED_HOSTS"):
                LiveIntegrations({"A2Z_INTEGRATION_ALLOWED_HOSTS": "bmc.example.test"}).probe_connection(
                    {**connector, "base_url": "https://bmc.example.test:8443"}
                )
        request.assert_not_called()

    def test_saved_mcp_connector_performs_discovery_and_tool_listing_without_calling_tools(self) -> None:
        integrations = LiveIntegrations({"A2Z_INTEGRATION_ALLOWED_HOSTS": "mcp.example.test"})
        connector = {"protocol": "mcp_http", "base_url": "https://mcp.example.test/mcp", "allowed_hosts": ["mcp.example.test"]}
        with patch("control_plane_core.live_integrations._request", side_effect=[
            ({"result": {"supportedVersions": ["2026-07-28"]}}, {}),
            ({"result": {"tools": [{"name": "inventory.search"}]}}, {}),
        ]) as request:
            result = integrations.probe_connection(connector)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[0].kwargs["body"]["method"], "server/discover")
        self.assertEqual(request.call_args_list[1].kwargs["body"]["method"], "tools/list")
        self.assertEqual(result["diagnostics"]["protocol_version"], "2026-07-28")
        self.assertNotIsInstance(result["diagnostics"]["protocol_version"], dict)
        self.assertEqual(result["diagnostics"]["tools"], ["inventory.search"])
        self.assertFalse(result["execution_permitted"])

    def test_mcp_probe_discovers_modern_protocol_then_lists_tools(self) -> None:
        integrations = LiveIntegrations({
            "A2Z_MCP_SERVERS_JSON": '[{"id":"docs","url":"https://mcp.example.test/mcp"}]',
            "A2Z_MCP_ALLOWED_HOSTS": "mcp.example.test",
        })
        discover = {"result": {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}, "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "docs", "version": "1"}}}}
        listed = {"result": {"tools": [{"name": "search", "description": "Search docs"}]}}
        with patch("control_plane_core.live_integrations._request", side_effect=[(discover, {}), (listed, {})]) as request:
            result = integrations.mcp_tools()
        self.assertEqual(result["servers"][0]["status"], "connected")
        self.assertEqual(result["servers"][0]["tools"][0]["name"], "search")
        self.assertEqual(result["servers"][0]["protocol_version"], "2026-07-28")
        self.assertFalse(result["tool_execution"])
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[0].kwargs["body"]["method"], "server/discover")
        self.assertEqual(request.call_args_list[1].kwargs["body"]["method"], "tools/list")
        self.assertEqual(request.call_args_list[1].kwargs["body"]["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28")

    def test_mcp_probe_falls_back_to_legacy_after_discovery_not_found(self) -> None:
        integrations = LiveIntegrations({
            "A2Z_MCP_SERVERS_JSON": '[{"id":"docs","url":"https://mcp.example.test/mcp"}]',
            "A2Z_MCP_ALLOWED_HOSTS": "mcp.example.test",
        })
        init = {"result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "docs", "version": "1"}}}
        listed = {"result": {"tools": [{"name": "search", "description": "Search docs"}]}}
        with patch("control_plane_core.live_integrations._request", side_effect=[
            ConnectionError("remote endpoint returned HTTP 404"), (init, {"MCP-Session-Id": "legacy-session"}), ({}, {}), (listed, {}),
        ]) as request:
            result = integrations.mcp_tools()
        self.assertEqual(result["servers"][0]["status"], "connected")
        self.assertEqual(result["servers"][0]["protocol_version"], "2025-11-25")
        self.assertEqual(request.call_args_list[1].kwargs["body"]["method"], "initialize")
        self.assertEqual(request.call_args_list[2].kwargs["body"]["method"], "notifications/initialized")
        self.assertEqual(request.call_args_list[3].kwargs["body"]["method"], "tools/list")

    def test_mcp_remote_host_requires_explicit_allowlist(self) -> None:
        integrations = LiveIntegrations({
            "A2Z_MCP_SERVERS_JSON": '[{"id":"docs","url":"https://mcp.example.test/mcp"}]',
        })
        with patch("control_plane_core.live_integrations._request") as request:
            result = integrations.mcp_tools()
        self.assertEqual(result["servers"][0]["status"], "error")
        self.assertIn("A2Z_MCP_ALLOWED_HOSTS", result["servers"][0]["error"])
        request.assert_not_called()

    def test_http_routes_are_live_but_missing_credentials_fail_closed(self) -> None:
        api = LocalControlPlaneApi()
        status, payload = api.dispatch("GET", "/v1/integrations/openrouter/models")
        self.assertEqual(status, 400)
        self.assertIn("not configured", payload["error"])
        status, payload = api.dispatch("GET", "/v1/integrations/mcp/tools")
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 0)
        self.assertFalse(payload["tool_execution"])


if __name__ == "__main__":
    unittest.main()
