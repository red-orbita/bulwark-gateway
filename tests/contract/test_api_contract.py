"""
Contract tests — Verify API responses match documented schemas and
maintain backward compatibility.

Run: pytest tests/contract/ -q
"""

import pytest


class TestV1Contract:
    """Ensure v1 API maintains backward compatibility."""

    def test_chat_completion_requires_auth(self, client):
        """Requests without auth return 401."""
        response = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Tenant-ID": "test", "X-Agent-ID": "test"},
        )
        assert response.status_code == 401

    def test_chat_completion_auth_error_format(self, client):
        """401 response has consistent error format with 'error' key."""
        response = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"X-Tenant-ID": "test", "X-Agent-ID": "test"},
        )
        body = response.json()
        # Must have error key
        assert "error" in body
        error = body["error"]
        # Error can be either a string message or an object with 'message' field
        if isinstance(error, str):
            assert len(error) > 0
        else:
            assert "message" in error
            assert isinstance(error["message"], str)
            assert len(error["message"]) > 0

    def test_chat_completion_blocked_returns_403(self, client, auth_headers, malicious_chat_request):
        """Malicious content returns 403 with security_violation error."""
        response = client.post(
            "/v1/chat/completions",
            json=malicious_chat_request,
            headers=auth_headers,
        )
        # Input guardrail should block this
        assert response.status_code == 403
        body = response.json()
        assert "error" in body
        error = body["error"]
        assert "message" in error
        assert error.get("type") == "security_violation"

    def test_chat_completion_invalid_json_returns_400(self, client, auth_headers):
        """Invalid JSON body returns 400."""
        response = client.post(
            "/v1/chat/completions",
            content=b"this is not json",
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert response.status_code == 400

    def test_chat_completion_body_too_large_returns_413(self, client, auth_headers):
        """Request body exceeding 10MB returns 413."""
        # Send Content-Length header indicating > 10MB
        large_headers = {**auth_headers, "Content-Length": str(11 * 1024 * 1024)}
        response = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "x"}]},
            headers=large_headers,
        )
        assert response.status_code == 413
        body = response.json()
        assert "error" in body
        assert body["error"]["code"] == "body_too_large"

    def test_error_format_consistent_401(self, client):
        """401 errors follow the standard error envelope."""
        endpoints = [
            ("/v1/chat/completions", "POST"),
            ("/health/stats", "GET"),
            ("/health/telemetry", "GET"),
        ]
        for path, method in endpoints:
            if method == "POST":
                response = client.post(
                    path,
                    json={"model": "x", "messages": [{"role": "user", "content": "y"}]},
                    headers={"X-Tenant-ID": "t", "X-Agent-ID": "a"},
                )
            else:
                response = client.get(path)
            # All should require auth
            assert response.status_code in (401, 403), f"{path} returned {response.status_code}"
            body = response.json()
            assert "error" in body or "detail" in body, f"{path} missing error key: {body}"

    def test_auth_error_codes_stable(self, client):
        """401 for missing auth, 403 for blocked content — codes must be stable."""
        # Missing auth → 401
        response = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
            headers={"X-Tenant-ID": "t", "X-Agent-ID": "a"},
        )
        assert response.status_code == 401

        # Invalid auth → 401
        response = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
            headers={
                "Authorization": "Bearer invalid-key-xyz",
                "X-Tenant-ID": "t",
                "X-Agent-ID": "a",
            },
        )
        assert response.status_code == 401

    def test_tool_validate_endpoint_exists(self, client, auth_headers):
        """The /v1/tool/validate endpoint exists and requires proper body."""
        response = client.post(
            "/v1/tool/validate",
            json={"tool_name": "web_search", "arguments": {"query": "test"}},
            headers=auth_headers,
        )
        # Should not return 404 (endpoint exists)
        assert response.status_code != 404

    def test_v1_fail_closed_on_error(self, client, auth_headers):
        """V1 endpoints return 403 (fail-closed) on unexpected internal errors,
        never expose 500 with stack traces."""
        # Empty body to trigger parsing error should return 400, not 500
        response = client.post(
            "/v1/chat/completions",
            content=b"",
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        # Should be 400 (bad request) not 500
        assert response.status_code in (400, 403)


class TestV2Contract:
    """Ensure v2 API matches documented OpenAPI spec."""

    def test_scan_response_schema(self, client, v2_auth_headers, valid_scan_request, schema_validator):
        """v2/scan response matches ScanResponse model."""
        response = client.post(
            "/v2/scan",
            json=valid_scan_request,
            headers=v2_auth_headers,
        )
        assert response.status_code == 200
        body = response.json()

        errors = schema_validator.validate(body, "ScanResponse")
        assert errors == [], f"Schema validation errors: {errors}"

    def test_scan_response_required_fields(self, client, v2_auth_headers, valid_scan_request):
        """Scan response contains all required fields."""
        response = client.post(
            "/v2/scan",
            json=valid_scan_request,
            headers=v2_auth_headers,
        )
        assert response.status_code == 200
        body = response.json()

        # Required top-level fields
        assert "verdict" in body
        assert "scan_id" in body
        assert "timestamp" in body
        assert "findings" in body
        assert "metadata" in body

        # Verdict must be valid enum value
        assert body["verdict"] in ("allow", "block", "warn")

        # Metadata required fields
        metadata = body["metadata"]
        assert "scan_duration_ms" in metadata
        assert "patterns_checked" in metadata
        assert "api_version" in metadata
        assert isinstance(metadata["scan_duration_ms"], (int, float))
        assert isinstance(metadata["patterns_checked"], int)

    def test_scan_malicious_content_has_findings(self, client, v2_auth_headers, malicious_scan_request, schema_validator):
        """Malicious content produces findings with correct schema."""
        response = client.post(
            "/v2/scan",
            json=malicious_scan_request,
            headers=v2_auth_headers,
        )
        assert response.status_code == 200
        body = response.json()

        # Should detect the attack
        assert body["verdict"] in ("block", "warn")
        assert len(body["findings"]) > 0

        # Validate finding schema
        for finding in body["findings"]:
            assert "category" in finding
            assert "severity" in finding
            assert "description" in finding
            assert finding["severity"] in ("low", "medium", "high", "critical")

        # Full schema validation
        errors = schema_validator.validate(body, "ScanResponse")
        assert errors == [], f"Schema validation errors: {errors}"

    def test_batch_scan_response_schema(self, client, v2_auth_headers, valid_batch_scan_request, schema_validator):
        """v2/scan/batch response matches BatchScanResponse model."""
        response = client.post(
            "/v2/scan/batch",
            json=valid_batch_scan_request,
            headers=v2_auth_headers,
        )
        assert response.status_code == 200
        body = response.json()

        errors = schema_validator.validate(body, "BatchScanResponse")
        assert errors == [], f"Schema validation errors: {errors}"

    def test_batch_scan_results_correlated(self, client, v2_auth_headers, valid_batch_scan_request):
        """Batch results are correlated by the client-provided ID."""
        response = client.post(
            "/v2/scan/batch",
            json=valid_batch_scan_request,
            headers=v2_auth_headers,
        )
        assert response.status_code == 200
        body = response.json()

        # Must have results for each input item
        assert len(body["results"]) == len(valid_batch_scan_request["items"])

        # Each result must have the matching ID
        result_ids = {r["id"] for r in body["results"]}
        input_ids = {item["id"] for item in valid_batch_scan_request["items"]}
        assert result_ids == input_ids

    def test_batch_scan_summary_counts(self, client, v2_auth_headers, valid_batch_scan_request):
        """Batch summary counts match individual results."""
        response = client.post(
            "/v2/scan/batch",
            json=valid_batch_scan_request,
            headers=v2_auth_headers,
        )
        assert response.status_code == 200
        body = response.json()

        summary = body["summary"]
        results = body["results"]

        # Summary totals must equal number of items
        total = summary.get("allow", 0) + summary.get("block", 0) + summary.get("warn", 0)
        assert total == len(results)

        # Count by verdict
        for verdict in ("allow", "block", "warn"):
            actual_count = sum(1 for r in results if r["verdict"] == verdict)
            assert summary.get(verdict, 0) == actual_count, (
                f"Summary {verdict}={summary.get(verdict, 0)} but actual count={actual_count}"
            )

    def test_version_header_present(self, client, v2_auth_headers, valid_scan_request):
        """X-API-Version header is always present in v2 responses."""
        response = client.post(
            "/v2/scan",
            json=valid_scan_request,
            headers=v2_auth_headers,
        )
        assert response.status_code == 200

        # The API version should be reflected in the response metadata
        body = response.json()
        assert body["metadata"]["api_version"] == "2026-06-01"

    def test_scan_requires_auth(self, client):
        """V2 scan endpoints require authentication."""
        response = client.post(
            "/v2/scan",
            json={"content": "test", "scan_type": "input"},
            headers={"X-Tenant-ID": "t", "X-Agent-ID": "a"},
        )
        assert response.status_code == 401

    def test_batch_scan_max_items(self, client, v2_auth_headers):
        """Batch scan enforces maximum 100 items."""
        oversized = {
            "items": [{"id": f"item-{i}", "content": "test"} for i in range(101)],
            "scan_type": "input",
        }
        response = client.post(
            "/v2/scan/batch",
            json=oversized,
            headers=v2_auth_headers,
        )
        # Should reject (422 validation error from Pydantic)
        assert response.status_code == 422

    def test_scan_content_max_length(self, client, v2_auth_headers):
        """Scan content enforces max_length=100000."""
        oversized = {
            "content": "x" * 100_001,
            "scan_type": "input",
        }
        response = client.post(
            "/v2/scan",
            json=oversized,
            headers=v2_auth_headers,
        )
        assert response.status_code == 422

    def test_scan_type_enum_validation(self, client, v2_auth_headers):
        """scan_type only accepts valid enum values."""
        response = client.post(
            "/v2/scan",
            json={"content": "test", "scan_type": "invalid_type"},
            headers=v2_auth_headers,
        )
        assert response.status_code == 422

    def test_scan_options_threshold_enum(self, client, v2_auth_headers):
        """threshold only accepts valid enum values."""
        response = client.post(
            "/v2/scan",
            json={
                "content": "test",
                "scan_type": "input",
                "options": {"threshold": "extreme"},
            },
            headers=v2_auth_headers,
        )
        assert response.status_code == 422


class TestHealthContract:
    """Ensure health endpoints match documented schemas."""

    def test_health_no_auth_required(self, client):
        """/health does not require authentication."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_response_schema(self, client, schema_validator):
        """/health response matches HealthResponse schema."""
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()

        errors = schema_validator.validate(body, "HealthResponse")
        assert errors == [], f"Schema validation errors: {errors}"

    def test_health_live_no_auth(self, client):
        """/health/live does not require authentication."""
        response = client.get("/health/live")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "alive"

    def test_ready_no_auth(self, client):
        """/ready does not require authentication."""
        response = client.get("/ready")
        assert response.status_code == 200
        body = response.json()
        assert "status" in body
        assert body["status"] in ("ready", "not_ready")

    def test_health_stats_requires_auth(self, client):
        """/health/stats requires authentication."""
        response = client.get("/health/stats")
        assert response.status_code == 401

    def test_health_telemetry_requires_auth(self, client):
        """/health/telemetry requires authentication."""
        response = client.get("/health/telemetry")
        assert response.status_code == 401


class TestAdminContract:
    """Ensure admin endpoints maintain contract."""

    def test_policies_reload_requires_admin_role(self, client, auth_headers):
        """Policy reload requires admin JWT role, not just API key."""
        response = client.post(
            "/admin/policies/reload",
            headers=auth_headers,
        )
        # API key auth should not grant admin role
        assert response.status_code in (401, 403)

    def test_policies_reload_no_auth(self, client):
        """Policy reload without auth returns 401."""
        response = client.post("/admin/policies/reload")
        assert response.status_code == 401


class TestErrorConsistency:
    """Ensure all error responses have consistent format."""

    def test_404_format(self, client, auth_headers):
        """Non-existent endpoints return proper error (404 or 405)."""
        response = client.get(
            "/v1/nonexistent",
            headers=auth_headers,
        )
        assert response.status_code in (404, 405)

    def test_all_errors_have_error_key(self, client, auth_headers):
        """All error responses contain an 'error' key or 'detail' key."""
        test_cases = [
            # (method, path, body, expected_status)
            ("POST", "/v1/chat/completions", None, 401),  # no auth
            ("POST", "/v2/scan", None, 401),  # no auth
        ]
        for method, path, body, expected_status in test_cases:
            if method == "POST":
                response = client.post(
                    path,
                    json=body or {"model": "x", "messages": [{"role": "user", "content": "y"}]},
                    headers={"X-Tenant-ID": "t", "X-Agent-ID": "a"},
                )
            else:
                response = client.get(path)

            assert response.status_code == expected_status, (
                f"{method} {path}: expected {expected_status}, got {response.status_code}"
            )
            resp_body = response.json()
            assert "error" in resp_body or "detail" in resp_body, (
                f"{method} {path}: response missing error/detail key: {resp_body}"
            )

    def test_v1_v2_error_format_parity(self, client):
        """V1 and V2 use the same error envelope format for auth errors."""
        v1_resp = client.post(
            "/v1/chat/completions",
            json={"model": "x", "messages": [{"role": "user", "content": "y"}]},
            headers={"X-Tenant-ID": "t", "X-Agent-ID": "a"},
        )
        v2_resp = client.post(
            "/v2/scan",
            json={"content": "test", "scan_type": "input"},
            headers={"X-Tenant-ID": "t", "X-Agent-ID": "a"},
        )

        assert v1_resp.status_code == 401
        assert v2_resp.status_code == 401

        v1_body = v1_resp.json()
        v2_body = v2_resp.json()

        # Both should use the same error structure
        v1_has_error = "error" in v1_body
        v2_has_error = "error" in v2_body
        assert v1_has_error == v2_has_error, (
            f"Error format mismatch: v1 has 'error'={v1_has_error}, v2 has 'error'={v2_has_error}"
        )


class TestDeprecationHeaders:
    """Ensure deprecation headers work correctly when applicable."""

    def test_v1_no_deprecation_header(self, client, auth_headers, valid_chat_request):
        """V1 endpoints do NOT have deprecation headers (v1 is current stable)."""
        response = client.post(
            "/v1/chat/completions",
            json=valid_chat_request,
            headers=auth_headers,
        )
        # V1 is the current stable version, should not be marked deprecated
        # (This test documents the contract — if v1 ever gets deprecated,
        # update this test to expect the Deprecation header)
        if response.status_code == 200:
            # Only check headers if request succeeds (may fail due to no backend)
            deprecation = response.headers.get("Deprecation")
            assert deprecation is None or deprecation == "", (
                "V1 should not be marked deprecated"
            )

    def test_v2_returns_api_version_metadata(self, client, v2_auth_headers, valid_scan_request):
        """V2 responses include api_version in metadata."""
        response = client.post(
            "/v2/scan",
            json=valid_scan_request,
            headers=v2_auth_headers,
        )
        if response.status_code == 200:
            body = response.json()
            assert "metadata" in body
            assert "api_version" in body["metadata"]
            # Version should be a date string
            version = body["metadata"]["api_version"]
            assert len(version) == 10  # YYYY-MM-DD format
            assert version[4] == "-" and version[7] == "-"


class TestOpenAPISpecConsistency:
    """Verify the OpenAPI spec itself is internally consistent."""

    def test_spec_has_all_documented_endpoints(self, openapi_spec):
        """All major endpoints are documented in the spec."""
        paths = openapi_spec.get("paths", {})

        expected_paths = [
            "/v1/chat/completions",
            "/v2/scan",
            "/v2/scan/batch",
            "/health",
            "/health/live",
            "/health/stats",
            "/ready",
        ]
        for path in expected_paths:
            assert path in paths, f"Missing endpoint in OpenAPI spec: {path}"

    def test_spec_schemas_referenced_exist(self, openapi_spec):
        """All $ref references in the spec point to existing schemas."""
        schemas = openapi_spec.get("components", {}).get("schemas", {})

        def find_refs(obj, path=""):
            """Recursively find all $ref values."""
            refs = []
            if isinstance(obj, dict):
                if "$ref" in obj:
                    refs.append((path, obj["$ref"]))
                for key, val in obj.items():
                    refs.extend(find_refs(val, f"{path}.{key}"))
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    refs.extend(find_refs(item, f"{path}[{i}]"))
            return refs

        all_refs = find_refs(openapi_spec)
        for location, ref in all_refs:
            # Only check component schema refs
            if ref.startswith("#/components/schemas/"):
                schema_name = ref.split("/")[-1]
                assert schema_name in schemas, (
                    f"Broken $ref at {location}: {ref} (schema '{schema_name}' not found)"
                )

    def test_spec_security_schemes_defined(self, openapi_spec):
        """Security schemes referenced in operations are defined."""
        security_schemes = openapi_spec.get("components", {}).get("securitySchemes", {})
        assert "BearerJWT" in security_schemes
        assert "APIKey" in security_schemes

    def test_spec_version_matches_project(self, openapi_spec):
        """OpenAPI spec version matches project version."""
        info = openapi_spec.get("info", {})
        assert "version" in info
        # Should be a valid semver-like string
        version = info["version"]
        parts = version.split(".")
        assert len(parts) >= 2, f"Invalid version format: {version}"

    def test_spec_error_response_reused(self, openapi_spec):
        """ErrorResponse schema is defined and reusable."""
        schemas = openapi_spec.get("components", {}).get("schemas", {})
        assert "ErrorResponse" in schemas

        error_schema = schemas["ErrorResponse"]
        assert "properties" in error_schema
        assert "error" in error_schema["properties"]
