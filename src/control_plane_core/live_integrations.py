"""Read-only, explicitly configured integration probes for the local console.

No provider endpoint or credential is accepted from an HTTP request. All
destinations and secrets are administrator-provided process configuration.
"""
from __future__ import annotations

import json
import os
import socket
import base64
import time
import urllib.error
import urllib.parse
import urllib.request
import datetime as dt
import re
from decimal import Decimal, InvalidOperation
from typing import Any

_TIMEOUT = 8
_MAX_RESPONSE = 2_000_000
_OPENROUTER_MODELS = "https://openrouter.ai/api/v1/models"
_AZURE_RETAIL_PRICES = "https://prices.azure.com/api/retail/prices"
_AZURE_RETAIL_API_VERSION = "2023-01-01-preview"
_GOOGLE_BILLING_BASE = "https://cloudbilling.googleapis.com/v1"
_GOOGLE_BILLING_MAX_SKU_PAGE = 200


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _configured_url(url: str, label: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{label} URL must be an absolute HTTP(S) URL without userinfo")
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError(f"{label} URL must use HTTPS except for loopback development endpoints")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{label} URL must not contain a query or fragment")
    return parsed


def _admin_origin_allowed(host: str, port: int, allowed_origins: set[str]) -> bool:
    """Host-only entries authorize standard HTTPS only; nonstandard ports must be explicit."""
    for entry in allowed_origins:
        candidate = entry.strip().lower().rstrip(".")
        if candidate.startswith("[") and "]" in candidate:
            closing = candidate.index("]")
            entry_host = candidate[1:closing]
            suffix = candidate[closing + 1:]
            entry_port = int(suffix[1:]) if suffix.startswith(":") and suffix[1:].isdigit() else 443 if not suffix else -1
        elif candidate.count(":") == 1 and candidate.rsplit(":", 1)[1].isdigit():
            entry_host, port_text = candidate.rsplit(":", 1)
            entry_port = int(port_text)
        else:
            entry_host, entry_port = candidate, 443
        if entry_host == host and entry_port == port:
            return True
    return False


def _request(url: str, *, token: str = "", method: str = "GET", body: dict[str, Any] | None = None,
             extra_headers: dict[str, str] | None = None) -> tuple[dict[str, Any], dict[str, str]]:
    headers = {"Accept": "application/json", "User-Agent": "OpsAtlas-local-console/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=_TIMEOUT) as response:
            raw = response.read(_MAX_RESPONSE + 1)
            if len(raw) > _MAX_RESPONSE:
                raise ValueError("integration response exceeded the 2 MB safety limit")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if not raw and response.status in {202, 204}:
                decoded = {}
            elif content_type == "text/event-stream":
                events = [line[5:].strip() for line in raw.decode("utf-8", "replace").splitlines() if line.startswith("data:")]
                decoded = json.loads(events[-1]) if events else {}
            else:
                decoded = json.loads(raw or b"{}")
            if not isinstance(decoded, dict):
                raise ValueError("integration returned an unexpected JSON shape")
            response_headers = dict(response.headers.items())
            response_headers["opsatlas-http-status"] = str(response.status)
            response_headers["opsatlas-content-type"] = content_type
            return decoded, response_headers
    except urllib.error.HTTPError as exc:
        # Never return remote error bodies: they may contain secrets or internals.
        raise ConnectionError(f"remote endpoint returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        reason = getattr(exc, "reason", None)
        kind = type(reason).__name__ if reason is not None else type(exc).__name__
        raise ConnectionError(f"connection failed ({kind})") from None
    except json.JSONDecodeError:
        raise ConnectionError("remote endpoint did not return valid JSON") from None


class LiveIntegrations:
    """Live but read-only probes; configured only through process environment."""

    def __init__(self, environ: dict[str, str] | None = None) -> None:
        self.environ = environ if environ is not None else os.environ

    def status(self) -> dict[str, Any]:
        openrouter_key = bool(self.environ.get("A2Z_OPENROUTER_API_KEY"))
        vllm_url = self.environ.get("A2Z_VLLM_BASE_URL", "").rstrip("/")
        servers = self._mcp_servers()
        return {
            "providers": [
                {"id": "openrouter", "name": "OpenRouter", "configured": openrouter_key, "capability": "model-catalog-read"},
                {"id": "vllm", "name": "vLLM", "configured": bool(vllm_url), "capability": "model-catalog-read"},
                {"id": "mcp", "name": "MCP servers", "configured": bool(servers), "capability": "initialize-and-tools-list"},
            ],
            "credentials_returned": False,
            "tool_execution": False,
        }

    def models(self, provider: str) -> dict[str, Any]:
        if provider == "openrouter":
            token = self.environ.get("A2Z_OPENROUTER_API_KEY", "")
            if not token:
                raise ValueError("A2Z_OPENROUTER_API_KEY is not configured")
            payload, _ = _request(_OPENROUTER_MODELS, token=token)
            models = payload.get("data")
        elif provider == "vllm":
            base = self.environ.get("A2Z_VLLM_BASE_URL", "").rstrip("/")
            if not base:
                raise ValueError("A2Z_VLLM_BASE_URL is not configured")
            parsed = _configured_url(base, "vLLM")
            token = self.environ.get("A2Z_VLLM_API_KEY", "")
            payload, _ = _request(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/v1/models", "", "")), token=token)
            models = payload.get("data")
        else:
            raise ValueError("provider must be openrouter or vllm")
        if not isinstance(models, list):
            raise ConnectionError("provider response did not contain a model list")
        safe_models = []
        for item in models[:500]:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                safe_models.append({"id": item["id"], "name": item.get("name") if isinstance(item.get("name"), str) else item["id"]})
        return {"provider": provider, "models": safe_models, "count": len(safe_models), "read_only": True}

    def azure_retail_prices(self, *, service_name: str, region: str = "", sku: str = "", currency: str = "USD") -> dict[str, Any]:
        """Read one bounded page from Microsoft's public retail catalog; never follows nextPageLink."""
        service_name = service_name.strip()
        region, sku, currency = region.strip(), sku.strip(), currency.strip().upper()
        if not service_name or len(service_name) > 80 or not re.fullmatch(r"[A-Za-z0-9 ()&._/-]+", service_name):
            raise ValueError("service_name is required and may contain only catalog-safe characters")
        if len(region) > 80 or (region and not re.fullmatch(r"[A-Za-z0-9._-]+", region)):
            raise ValueError("region contains unsupported characters or is too long")
        if len(sku) > 80 or (sku and not re.fullmatch(r"[A-Za-z0-9._-]+", sku)):
            raise ValueError("sku contains unsupported characters or is too long")
        if not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValueError("currency must be a three-letter ISO currency code")
        filters = [f"serviceName eq '{service_name.replace(chr(39), chr(39) * 2)}'"]
        if region:
            filters.append(f"armRegionName eq '{region}'")
        if sku:
            filters.append(f"armSkuName eq '{sku}'")
        filters.append("priceType eq 'Consumption'")
        query = urllib.parse.urlencode({
            "api-version": _AZURE_RETAIL_API_VERSION,
            "$filter": " and ".join(filters),
            "currencyCode": currency,
        })
        payload, _ = _request(f"{_AZURE_RETAIL_PRICES}?{query}")
        items = payload.get("Items")
        if not isinstance(items, list):
            raise ConnectionError("Azure price response did not match the retail catalog contract")
        rows = []
        for item in items[:100]:
            if not isinstance(item, dict):
                continue
            try:
                price = Decimal(str(item["retailPrice"]))
            except (KeyError, InvalidOperation, ValueError):
                continue
            if not price.is_finite() or price < 0:
                continue
            rows.append({key: item.get(key) for key in (
                "serviceName", "productName", "skuName", "armSkuName", "armRegionName",
                "meterName", "unitOfMeasure", "currencyCode", "effectiveStartDate",
                "priceType", "isPrimaryMeterRegion",
            )} | {"retailPrice": str(price)})
        return {
            "provider": "Microsoft Azure Retail Prices API",
            "api_version": _AZURE_RETAIL_API_VERSION,
            "retrieved_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source_url": _AZURE_RETAIL_PRICES,
            "query": {"service_name": service_name, "region": region or None, "sku": sku or None, "currency": currency},
            "prices": rows,
            "returned": len(rows),
            "truncated": len(items) > 100 or bool(payload.get("NextPageLink")),
            "commercial_basis": "Public retail list rates only; excludes negotiated discounts, tax, support, and customer-specific terms.",
            "persisted": False,
            "execution_permitted": False,
        }

    def google_cloud_retail_prices(self, *, service_name: str, region: str, sku_query: str, currency: str = "USD") -> dict[str, Any]:
        """Search one bounded page of Google's public billing catalog using a server-side API key."""
        service_name, region, sku_query = service_name.strip(), region.strip(), sku_query.strip()
        currency = currency.strip().upper()
        if not service_name or len(service_name) > 80 or not re.fullmatch(r"[A-Za-z0-9 &()._/-]+", service_name):
            raise ValueError("service_name is required and may contain only catalog-safe characters")
        if not region or len(region) > 80 or not re.fullmatch(r"[A-Za-z0-9._-]+", region):
            raise ValueError("a valid Google Cloud region is required")
        if not sku_query or len(sku_query) > 100 or not re.fullmatch(r"[A-Za-z0-9 &()._/-]+", sku_query):
            raise ValueError("sku_query is required and may contain only catalog-safe characters")
        if not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValueError("currency must be a three-letter ISO currency code")
        api_key = self.environ.get("GOOGLE_CLOUD_BILLING_API_KEY", "").strip()
        if not api_key:
            raise ConnectionError("GOOGLE_CLOUD_BILLING_API_KEY is not configured in the server environment")
        if len(api_key) > 512 or any(ch in api_key for ch in "\r\n\x00"):
            raise ValueError("Google Cloud Billing API key configuration is invalid")

        service_query = urllib.parse.urlencode({"pageSize": 5000, "key": api_key})
        services, _ = _request(f"{_GOOGLE_BILLING_BASE}/services?{service_query}")
        matches = [item for item in services.get("services", []) if isinstance(item, dict) and str(item.get("displayName", "")).casefold() == service_name.casefold()]
        service = next((item for item in matches if re.fullmatch(r"[A-Za-z0-9-]{4,40}", str(item.get("serviceId", "")))), None)
        if service is None:
            raise ValueError("service name did not match a public Google Cloud catalog service")

        sku_query_url = urllib.parse.urlencode({"pageSize": _GOOGLE_BILLING_MAX_SKU_PAGE, "currencyCode": currency, "key": api_key})
        catalog, _ = _request(f"{_GOOGLE_BILLING_BASE}/services/{urllib.parse.quote(service['serviceId'], safe='')}/skus?{sku_query_url}")
        candidates = catalog.get("skus")
        if not isinstance(candidates, list):
            raise ConnectionError("Google Cloud Billing SKU response did not match the catalog contract")
        needle, rows = sku_query.casefold(), []
        for sku in candidates:
            if not isinstance(sku, dict) or needle not in str(sku.get("description", "")).casefold():
                continue
            regions = sku.get("serviceRegions") if isinstance(sku.get("serviceRegions"), list) else []
            if regions and region not in regions:
                continue
            info = sku.get("pricingInfo") if isinstance(sku.get("pricingInfo"), list) else []
            latest = info[-1] if info and isinstance(info[-1], dict) else {}
            expression = latest.get("pricingExpression") if isinstance(latest.get("pricingExpression"), dict) else {}
            tiers, safe_tiers = expression.get("tieredRates"), []
            for tier in tiers if isinstance(tiers, list) else []:
                if not isinstance(tier, dict) or not isinstance(tier.get("unitPrice"), dict):
                    continue
                try:
                    amount = Decimal(str(tier["unitPrice"].get("units", "0"))) + Decimal(str(tier["unitPrice"].get("nanos", 0))) / Decimal(1_000_000_000)
                    threshold = Decimal(str(tier.get("startUsageAmount", "0")))
                except (InvalidOperation, ValueError, TypeError):
                    continue
                if amount.is_finite() and amount >= 0 and threshold.is_finite() and threshold >= 0:
                    safe_tiers.append({"start_usage_amount": str(threshold), "unit_price": str(amount)})
            simple = len(safe_tiers) == 1 and Decimal(safe_tiers[0]["start_usage_amount"]) == 0
            category = sku.get("category") if isinstance(sku.get("category"), dict) else {}
            rows.append({
                "serviceName": service_name, "serviceId": service["serviceId"],
                "skuId": str(sku.get("skuId", "")), "description": str(sku.get("description", ""))[:256],
                "region": region, "available_regions": regions[:100], "usage_type": str(category.get("usageType", "")),
                "currencyCode": currency, "unitOfMeasure": str(expression.get("usageUnitDescription") or expression.get("usageUnit") or ""),
                "effectiveStartDate": latest.get("effectiveTime"), "tiered_rates": safe_tiers,
                "tier_count": len(safe_tiers), "estimate_eligible": simple,
                "retailPrice": safe_tiers[0]["unit_price"] if simple else None,
            })
            if len(rows) >= 100:
                break
        return {
            "provider": "Google Cloud Billing Catalog API", "api_version": "v1",
            "retrieved_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source_url": f"{_GOOGLE_BILLING_BASE}/services",
            "query": {"service_name": service_name, "region": region, "sku_query": sku_query, "currency": currency},
            "prices": rows, "returned": len(rows),
            "truncated": bool(catalog.get("nextPageToken")) or len(rows) >= 100,
            "commercial_basis": "Public Google Cloud catalog list rates; may use Google currency conversion; excludes account-specific contract pricing, taxes, support, and other bill adjustments.",
            "persisted": False, "execution_permitted": False,
        }

    def probe_connection(self, connection: dict[str, Any]) -> dict[str, Any]:
        """Run one explicitly allowlisted, read-only HTTP probe for a saved connection."""
        protocol = connection.get("protocol")
        if protocol not in {"rest_openapi", "redfish", "mcp_http"}:
            raise ValueError(f"no live adapter implemented for protocol {protocol!r}; no request was sent")
        raw_url = str(connection.get("base_url") or "")
        parsed = _configured_url(raw_url, str(protocol))
        host = (parsed.hostname or "").lower().rstrip(".")
        saved_hosts = {str(item).strip().lower().rstrip(".") for item in (connection.get("allowed_hosts") or [])}
        loopback = host in {"localhost", "127.0.0.1", "::1"}
        admin_hosts = {
            item.strip().lower().rstrip(".")
            for item in self.environ.get("A2Z_INTEGRATION_ALLOWED_HOSTS", "").split(",")
            if item.strip()
        }
        endpoint_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if host not in saved_hosts:
            raise PermissionError("endpoint host is not in this connector's saved exact-host allowlist")
        if not loopback and not _admin_origin_allowed(host, endpoint_port, admin_hosts):
            raise PermissionError("endpoint host is not in A2Z_INTEGRATION_ALLOWED_HOSTS")

        if protocol == "redfish":
            path = parsed.path.rstrip("/")
            if not path:
                path = "/redfish/v1/"
            elif path.lower().endswith("/redfish/v1"):
                path += "/"
            elif path.lower().endswith("/redfish/v1/"):
                pass
            else:
                path = path + "/redfish/v1/"
            target_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        else:
            target_url = raw_url

        credential_ref = str(connection.get("credential_ref") or "")
        token = self.environ.get(credential_ref, "") if credential_ref else ""
        if credential_ref and not token:
            raise ValueError("connector credential reference is not configured in the server environment")
        auth_scheme = str(connection.get("auth_scheme") or "bearer").lower()
        auth_headers: dict[str, str] = {}
        if auth_scheme == "http_basic":
            if protocol != "redfish" or ":" not in token:
                raise ValueError("HTTP Basic requires a Redfish connector and USERNAME:PASSWORD secret reference")
            auth_headers["Authorization"] = "Basic " + base64.b64encode(token.encode("utf-8")).decode("ascii")
            token = ""
        elif auth_scheme != "bearer":
            raise ValueError("unsupported connector authentication scheme")
        started = time.monotonic()
        mcp_result = None
        if protocol == "mcp_http":
            mcp_result = self._mcp_tools_at(target_url, token)
            payload, headers = {}, {"opsatlas-http-status": "200", "opsatlas-content-type": "application/json"}
        else:
            payload, headers = _request(target_url, token=token, extra_headers={
                "Accept": "application/json",
                **({"OData-Version": "4.0"} if protocol == "redfish" else {}),
                **auth_headers,
            })
        elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
        status_code = int(headers.get("opsatlas-http-status", "200"))
        content_type = headers.get("opsatlas-content-type", "")
        if protocol == "redfish":
            if not any(key in payload for key in ("RedfishVersion", "@odata.type", "@odata.id")):
                raise ConnectionError("response is JSON but does not match the Redfish service-root contract")
            details: dict[str, Any] = {
                "resource": payload.get("@odata.id", "/redfish/v1/"),
                "service_name": payload.get("Name") if isinstance(payload.get("Name"), str) else None,
                "redfish_version": payload.get("RedfishVersion") if isinstance(payload.get("RedfishVersion"), str) else None,
                "collections": {},
            }
            collection_errors = []
            for collection_name in ("Systems", "Chassis"):
                link = payload.get(collection_name)
                if not isinstance(link, dict) or not isinstance(link.get("@odata.id"), str):
                    continue
                collection_url = urllib.parse.urljoin(target_url.rstrip("/") + "/", link["@odata.id"])
                collection_parts = urllib.parse.urlsplit(collection_url)
                if (collection_parts.scheme != parsed.scheme or collection_parts.hostname != parsed.hostname
                        or collection_parts.port != parsed.port or collection_parts.username or collection_parts.password
                        or collection_parts.fragment):
                    collection_errors.append(collection_name)
                    continue
                try:
                    collection, _ = _request(collection_url, token=token, extra_headers={
                        "Accept": "application/json", "OData-Version": "4.0",
                        **auth_headers,
                    })
                    members = collection.get("Members")
                    details["collections"][collection_name] = {
                        "member_count": len(members) if isinstance(members, list) else 0,
                    }
                except (ValueError, ConnectionError):
                    collection_errors.append(collection_name)
            if collection_errors:
                details["collection_errors"] = collection_errors
            outcome = "partial" if collection_errors else "healthy"
        elif protocol == "mcp_http":
            assert mcp_result is not None
            outcome = "healthy"
            details = {"protocol_version": mcp_result["protocol_version"],
                       "tool_count": len(mcp_result["tools"]),
                       "tools": [tool["name"] for tool in mcp_result["tools"]]}
        else:
            is_openapi = isinstance(payload.get("openapi"), str) or isinstance(payload.get("swagger"), str)
            paths = payload.get("paths") if isinstance(payload.get("paths"), dict) else {}
            details = {
                "document_type": "openapi" if is_openapi else "json-api",
                "title": payload.get("info", {}).get("title") if isinstance(payload.get("info"), dict) else None,
                "version": payload.get("info", {}).get("version") if isinstance(payload.get("info"), dict) else None,
                "path_count": len(paths),
                "response_keys": sorted(str(key)[:80] for key in payload.keys())[:50],
            }
        return {
            "protocol": protocol,
            "outcome": outcome if protocol in {"redfish", "mcp_http"} else "healthy",
            "http_status": status_code,
            "latency_ms": elapsed_ms,
            "records_read": len(mcp_result["tools"]) if mcp_result is not None else 1,
            "content_type": content_type,
            "diagnostics": details,
            "read_only": True,
            "credentials_returned": False,
            "execution_permitted": False,
        }

    def _mcp_tools_at(self, endpoint: str, token: str) -> dict[str, Any]:
        preferred = self.environ.get("A2Z_MCP_PROTOCOL_VERSION", "2026-07-28")
        if preferred == "2026-07-28":
            client_meta = {
                "io.modelcontextprotocol/protocolVersion": preferred,
                "io.modelcontextprotocol/clientInfo": {"name": "opsatlas-local-console", "version": "0.1.0"},
                "io.modelcontextprotocol/clientCapabilities": {},
            }
            try:
                discover, _ = _request(endpoint, token=token, method="POST", extra_headers={
                    "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": preferred,
                }, body={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": client_meta}})
            except ConnectionError as exc:
                if not any(code in str(exc) for code in ("HTTP 400", "HTTP 404", "HTTP 405", "HTTP 501")):
                    raise
                discover = {"error": {"code": -32601}}
            discovery = discover.get("result") if isinstance(discover, dict) else None
            versions = discovery.get("supportedVersions", []) if isinstance(discovery, dict) else []
            if isinstance(discovery, dict) and "error" not in discover and (not versions or preferred in versions):
                listed, _ = _request(endpoint, token=token, method="POST", extra_headers={
                    "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": preferred,
                }, body={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": client_meta}})
                protocol_version = preferred
                tools_result = listed.get("result")
                tools = tools_result.get("tools", []) if isinstance(tools_result, dict) else []
            else:
                listed, protocol_version = self._legacy_mcp_tools(endpoint, token, "2025-11-25")
                tools_result = listed.get("result")
                tools = tools_result.get("tools", []) if isinstance(tools_result, dict) else []
        else:
            listed, protocol_version = self._legacy_mcp_tools(endpoint, token, preferred)
            tools_result = listed.get("result")
            tools = tools_result.get("tools", []) if isinstance(tools_result, dict) else []
        if "error" in listed or not isinstance(tools, list):
            raise ConnectionError("MCP tools/list was rejected")
        safe_tools = [{"name": item["name"]} for item in tools[:200]
                      if isinstance(item, dict) and isinstance(item.get("name"), str)]
        return {"protocol_version": protocol_version, "tools": safe_tools}

    def mcp_tools(self) -> dict[str, Any]:
        results = []
        for server in self._mcp_servers():
            server_id, url = server["id"], server["url"]
            try:
                parsed = _configured_url(url, f"MCP server {server_id}")
                loopback_hosts = {"127.0.0.1", "localhost", "::1"}
                allowed_hosts = {host.strip().lower() for host in self.environ.get("A2Z_MCP_ALLOWED_HOSTS", "").split(",") if host.strip()}
                if parsed.hostname.lower() not in loopback_hosts and parsed.hostname.lower() not in allowed_hosts:
                    raise ValueError(f"MCP server {server_id} host is not in A2Z_MCP_ALLOWED_HOSTS")
                token = self.environ.get(server.get("token_env", ""), "") if server.get("token_env") else ""
                endpoint = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
                preferred = self.environ.get("A2Z_MCP_PROTOCOL_VERSION", "2026-07-28")
                if preferred == "2026-07-28":
                    client_meta = {
                        "io.modelcontextprotocol/protocolVersion": preferred,
                        "io.modelcontextprotocol/clientInfo": {"name": "opsatlas-local-console", "version": "0.1.0"},
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                    discover_body = {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": client_meta}}
                    try:
                        discover, _ = _request(endpoint, token=token, method="POST", extra_headers={
                            "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": preferred,
                        }, body=discover_body)
                    except ConnectionError as exc:
                        if not any(code in str(exc) for code in ("HTTP 400", "HTTP 404", "HTTP 405", "HTTP 501")):
                            raise
                        discover = {"error": {"code": -32601}}
                    result = discover.get("result") if isinstance(discover, dict) else None
                    supported = result.get("supportedVersions", []) if isinstance(result, dict) else []
                    if isinstance(result, dict) and "error" not in discover and (not supported or preferred in supported):
                        listed, _ = _request(endpoint, token=token, method="POST", extra_headers={
                            "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": preferred,
                        }, body={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": client_meta}})
                        protocol_version = preferred
                    else:
                        listed, protocol_version = self._legacy_mcp_tools(endpoint, token, "2025-11-25")
                else:
                    listed, protocol_version = self._legacy_mcp_tools(endpoint, token, preferred)
                tools = listed.get("result", {}).get("tools", []) if isinstance(listed.get("result"), dict) else []
                if "error" in listed or not isinstance(tools, list):
                    raise ConnectionError("MCP tools/list was rejected")
                results.append({"id": server_id, "status": "connected", "tools": [
                    {"name": item.get("name", ""), "description": item.get("description", "")[:240]}
                    for item in tools[:200] if isinstance(item, dict) and isinstance(item.get("name"), str)
                ], "protocol_version": protocol_version, "tool_execution": False})
            except (ValueError, ConnectionError) as exc:
                results.append({"id": server_id, "status": "error", "error": str(exc), "tools": [], "tool_execution": False})
        return {"servers": results, "count": len(results), "tool_execution": False}

    def _legacy_mcp_tools(self, endpoint: str, token: str, protocol_version: str) -> tuple[dict[str, Any], str]:
        init, headers = _request(
            endpoint, token=token, method="POST",
            extra_headers={"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": protocol_version},
            body={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": protocol_version, "capabilities": {},
                "clientInfo": {"name": "opsatlas-local-console", "version": "0.1.0"}}},
        )
        init_result = init.get("result") if isinstance(init, dict) else None
        if "error" in init or not isinstance(init_result, dict):
            raise ConnectionError("MCP initialize was rejected")
        negotiated = init_result.get("protocolVersion", protocol_version)
        session_id = next((v for k, v in headers.items() if k.lower() == "mcp-session-id"), "")
        request_headers = {"MCP-Protocol-Version": negotiated}
        if session_id:
            request_headers["MCP-Session-Id"] = session_id
        _request(endpoint, token=token, method="POST", extra_headers=request_headers,
                 body={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        listed, _ = _request(endpoint, token=token, method="POST", extra_headers=request_headers,
                             body={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        return listed, negotiated

    def _mcp_servers(self) -> list[dict[str, str]]:
        raw = self.environ.get("A2Z_MCP_SERVERS_JSON", "[]")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError("A2Z_MCP_SERVERS_JSON must be valid JSON") from None
        if not isinstance(parsed, list) or len(parsed) > 20:
            raise ValueError("A2Z_MCP_SERVERS_JSON must be a list of at most 20 configured servers")
        servers: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in parsed:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("url"), str):
                raise ValueError("each MCP server needs string id and url fields")
            server_id = item["id"]
            if not server_id or len(server_id) > 64 or server_id in seen:
                raise ValueError("MCP server ids must be unique, non-empty, and at most 64 characters")
            token_env = item.get("token_env", "")
            if not isinstance(token_env, str) or (token_env and not token_env.startswith("A2Z_MCP_TOKEN_")):
                raise ValueError("MCP token_env must reference an A2Z_MCP_TOKEN_* environment variable")
            seen.add(server_id)
            servers.append({"id": server_id, "url": item["url"], "token_env": token_env})
        return servers
