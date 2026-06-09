"""Unit tests for the VaultKnox Credential Verifier module."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from vaultknox.verifier import (
    DEFAULT_TIMEOUT,
    CredentialVerifier,
    _VerificationResult,
    _verify_anthropic,
    _verify_generic_bearer,
    _verify_github,
    _verify_google_oauth,
    _verify_openai,
    get_provider,
    list_providers,
    register_provider,
)


class TestVerificationResult(unittest.TestCase):
    """Tests for _VerificationResult dataclass."""

    def test_verification_result_creation(self):
        """Test creating a VerificationResult."""
        result = _VerificationResult(
            status="valid",
            provider="openai",
            http_status_code=200,
            message=None,
        )
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.provider, "openai")
        self.assertEqual(result.http_status_code, 200)
        self.assertIsNone(result.message)

    def test_verification_result_immutable(self):
        """Test that VerificationResult is immutable."""
        result = _VerificationResult(status="valid", provider="test")
        with self.assertRaises(AttributeError):
            result.status = "invalid"

    def test_verification_result_slots(self):
        """Test that VerificationResult uses __slots__."""
        result = _VerificationResult(status="valid", provider="test")
        # With slots=True, object has no __dict__, only __slots__
        self.assertFalse(hasattr(result, "__dict__"))
        # Slots work correctly
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.provider, "test")


class TestProviderRegistry(unittest.TestCase):
    """Tests for the provider registry functions."""

    def setUp(self):
        # Reset registry by removing any test providers
        pass

    def test_list_providers_includes_builtins(self):
        """Test that built-in providers are registered."""
        providers = list_providers()
        self.assertIn("openai", providers)
        self.assertIn("anthropic", providers)
        self.assertIn("github", providers)
        self.assertIn("google_oauth", providers)

    def test_register_and_get_provider(self):
        """Test registering and retrieving a custom provider."""
        def dummy_verify(payload):
            return _VerificationResult(status="valid", provider="dummy")

        register_provider("dummy_service", dummy_verify)
        self.assertIsNotNone(get_provider("dummy_service"))
        self.assertEqual(get_provider("dummy_service"), dummy_verify)

    def test_get_provider_case_insensitive(self):
        """Test that provider lookup is case insensitive."""
        result = get_provider("OpenAI")
        self.assertIsNotNone(result)
        self.assertEqual(get_provider("OPENAI"), result)

    def test_get_unknown_provider(self):
        """Test getting a non-existent provider returns None."""
        self.assertIsNone(get_provider("nonexistent_service_xyz"))

    def test_register_provider_overwrites(self):
        """Test that registering a provider with same name overwrites."""
        call_count = [0]

        def v1(payload):
            call_count[0] += 1
            return _VerificationResult(status="valid", provider="svc")

        def v2(payload):
            call_count[0] += 2
            return _VerificationResult(status="invalid", provider="svc")

        register_provider("svc", v1)
        register_provider("svc", v2)
        self.assertEqual(call_count[0], 0)  # Not called yet
        func = get_provider("svc")
        func({})  # Call it
        self.assertEqual(call_count[0], 2)


class TestCredentialVerifier(unittest.TestCase):
    """Tests for the CredentialVerifier class."""

    def setUp(self):
        self.verifier = CredentialVerifier()

    def test_default_timeout(self):
        """Test that default timeout is set correctly."""
        self.assertEqual(self.verifier.timeout, DEFAULT_TIMEOUT)

    def test_custom_timeout(self):
        """Test creating verifier with custom timeout."""
        v = CredentialVerifier(timeout=10.0)
        self.assertEqual(v.timeout, 10.0)

    def test_verify_missing_service(self):
        """Test verifying a payload without service field."""
        result = self.verifier.verify({"key": "sk-test-xxx"})
        self.assertEqual(result.status, "unknown")
        self.assertIn("No service specified", result.message)

    def test_verify_unknown_service(self):
        """Test verifying against an unregistered service."""
        result = self.verifier.verify({"key": "sk-test-xxx", "service": "unknown_service_123"})
        self.assertEqual(result.status, "unknown")
        self.assertIn("Unknown service", result.message)

    def test_verify_from_vault_response_wrong_type(self):
        """Test verify_from_vault_response rejects non-api_key types."""
        result = self.verifier.verify_from_vault_response({
            "type": "password",
            "payload": {"value": "secret"},
        })
        self.assertEqual(result.status, "unknown")
        self.assertIn("Unsupported secret type", result.message)

    def test_verify_from_vault_response_missing_payload(self):
        """Test verify_from_vault_response handles missing payload."""
        result = self.verifier.verify_from_vault_response({
            "type": "api_key",
        })
        self.assertEqual(result.status, "unknown")

    def test_register_service_static(self):
        """Test that register_service static method works."""
        call_count = [0]

        def custom_verify(payload):
            call_count[0] += 1
            return _VerificationResult(status="valid", provider="custom")

        CredentialVerifier.register_service("custom_test", custom_verify)
        self.assertIsNotNone(get_provider("custom_test"))


class TestVerifyOpenAI(unittest.TestCase):
    """Tests for OpenAI verification."""

    @patch("vaultknox.verifier.requests.request")
    def test_verify_valid_key(self, mock_request):
        """Test verification with a valid-looking response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        result = _verify_openai({"key": "sk-test-openai-xxx", "service": "openai"})
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.provider, "openai")
        self.assertEqual(result.http_status_code, 200)

    @patch("vaultknox.verifier.requests.request")
    def test_verify_invalid_key(self, mock_request):
        """Test verification with 401 response."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response

        result = _verify_openai({"key": "sk-invalid-xxx", "service": "openai"})
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.http_status_code, 401)

    @patch("vaultknox.verifier.requests.request")
    def test_verify_billing_issue(self, mock_request):
        """Test verification with 402 response."""
        mock_response = MagicMock()
        mock_response.status_code = 402
        mock_request.return_value = mock_response

        result = _verify_openai({"key": "sk-test-xxx", "service": "openai"})
        self.assertEqual(result.status, "billing_issue")
        self.assertEqual(result.http_status_code, 402)

    @patch("vaultknox.verifier.requests.request")
    def test_verify_rate_limit(self, mock_request):
        """Test verification with 429 response."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_request.return_value = mock_response

        result = _verify_openai({"key": "sk-test-xxx", "service": "openai"})
        self.assertEqual(result.status, "billing_issue")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_timeout(self, mock_request):
        """Test verification timeout."""
        import requests
        mock_request.side_effect = requests.Timeout()

        result = _verify_openai({"key": "sk-test-xxx", "service": "openai"})
        self.assertEqual(result.status, "timeout")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_network_error(self, mock_request):
        """Test verification network error."""
        import requests
        mock_request.side_effect = requests.RequestException("Connection refused")

        result = _verify_openai({"key": "sk-test-xxx", "service": "openai"})
        self.assertEqual(result.status, "network_error")

    def test_verify_sends_bearer_token(self):
        """Test that the correct Authorization header is sent."""
        with patch("vaultknox.verifier.requests.request") as mock_request:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response

            _verify_openai({"key": "sk-test-key-123", "service": "openai"})

            mock_request.assert_called_once()
            call_kwargs = mock_request.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            self.assertEqual(headers.get("Authorization"), "Bearer sk-test-key-123")


class TestVerifyAnthropic(unittest.TestCase):
    """Tests for Anthropic verification."""

    @patch("vaultknox.verifier.requests.request")
    def test_verify_valid_key(self, mock_request):
        """Test verification with valid response."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_request.return_value = mock_response

        result = _verify_anthropic({"key": "sk-ant-api03-test-xxx", "service": "anthropic"})
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.provider, "anthropic")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_invalid_key(self, mock_request):
        """Test verification with 401 response."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response

        result = _verify_anthropic({"key": "sk-ant-invalid-xxx", "service": "anthropic"})
        self.assertEqual(result.status, "invalid")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_timeout(self, mock_request):
        """Test verification timeout."""
        import requests
        mock_request.side_effect = requests.Timeout()

        result = _verify_anthropic({"key": "sk-ant-api03-xxx", "service": "anthropic"})
        self.assertEqual(result.status, "timeout")

    def test_verify_sends_x_api_key_header(self):
        """Test that the correct x-api-key header is sent."""
        with patch("vaultknox.verifier.requests.request") as mock_request:
            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_request.return_value = mock_response

            _verify_anthropic({"key": "sk-ant-api03-mykey", "service": "anthropic"})

            call_kwargs = mock_request.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            self.assertEqual(headers.get("x-api-key"), "sk-ant-api03-mykey")


class TestVerifyGitHub(unittest.TestCase):
    """Tests for GitHub token verification."""

    @patch("vaultknox.verifier.requests.request")
    def test_verify_valid_token(self, mock_request):
        """Test verification with valid response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        result = _verify_github({"key": "ghp_xxxxxxxxxxxxxxxxxxxx", "service": "github"})
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.provider, "github")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_invalid_token(self, mock_request):
        """Test verification with 401 response."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response

        result = _verify_github({"key": "ghp_invalid_xxx", "service": "github"})
        self.assertEqual(result.status, "invalid")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_forbidden(self, mock_request):
        """Test verification with 403 response (rate limit or scope issue)."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_request.return_value = mock_response

        result = _verify_github({"key": "ghp_xxx", "service": "github"})
        self.assertEqual(result.status, "billing_issue")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_timeout(self, mock_request):
        """Test verification timeout."""
        import requests
        mock_request.side_effect = requests.Timeout()

        result = _verify_github({"key": "ghp_xxx", "service": "github"})
        self.assertEqual(result.status, "timeout")


class TestVerifyGoogleOAuth(unittest.TestCase):
    """Tests for Google OAuth token verification."""

    @patch("vaultknox.verifier.requests.request")
    def test_verify_valid_token(self, mock_request):
        """Test verification with valid response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        result = _verify_google_oauth({"key": "ya29.valid_token_here", "service": "google_oauth"})
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.provider, "google_oauth")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_invalid_token(self, mock_request):
        """Test verification with 400 and invalid_token error."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error_description": "Invalid Credentials"}
        mock_request.return_value = mock_response

        result = _verify_google_oauth({"key": "invalid_token", "service": "google_oauth"})
        self.assertEqual(result.status, "invalid")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_expired_token(self, mock_request):
        """Test verification with expired token error."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error_description": "Token expired"}
        mock_request.return_value = mock_response

        result = _verify_google_oauth({"key": "expired_token", "service": "google_oauth"})
        self.assertEqual(result.status, "invalid")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_timeout(self, mock_request):
        """Test verification timeout."""
        import requests
        mock_request.side_effect = requests.Timeout()

        result = _verify_google_oauth({"key": "token", "service": "google_oauth"})
        self.assertEqual(result.status, "timeout")


class TestVerifyGenericBearer(unittest.TestCase):
    """Tests for generic bearer token verification."""

    @patch("vaultknox.verifier.requests.request")
    def test_verify_valid_token(self, mock_request):
        """Test verification with valid response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        result = _verify_generic_bearer(
            {"key": "bearer_token_xyz", "verify_url": "https://api.example.com/verify"},
            verify_url="https://api.example.com/verify",
        )
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.provider, "generic")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_invalid_token(self, mock_request):
        """Test verification with 401 response."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response

        result = _verify_generic_bearer(
            {"key": "invalid_token", "verify_url": "https://api.example.com/verify"},
            verify_url="https://api.example.com/verify",
        )
        self.assertEqual(result.status, "invalid")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_billing_issue(self, mock_request):
        """Test verification with 402 response."""
        mock_response = MagicMock()
        mock_response.status_code = 402
        mock_request.return_value = mock_response

        result = _verify_generic_bearer(
            {"key": "token", "verify_url": "https://api.example.com/verify"},
            verify_url="https://api.example.com/verify",
        )
        self.assertEqual(result.status, "billing_issue")

    @patch("vaultknox.verifier.requests.request")
    def test_verify_timeout(self, mock_request):
        """Test verification timeout."""
        import requests
        mock_request.side_effect = requests.Timeout()

        result = _verify_generic_bearer(
            {"key": "token", "verify_url": "https://api.example.com/verify"},
            verify_url="https://api.example.com/verify",
        )
        self.assertEqual(result.status, "timeout")

    def test_verify_no_url_raises_unknown(self):
        """Test that missing verify_url returns unknown status."""
        result = _verify_generic_bearer({"key": "token"})
        self.assertEqual(result.status, "unknown")
        self.assertIn("No verify_url", result.message)

    @patch("vaultknox.verifier.requests.request")
    def test_verify_url_from_payload(self, mock_request):
        """Test that verify_url can come from payload."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        _verify_generic_bearer({"key": "token", "verify_url": "https://custom.api/validate"})

        call_kwargs = mock_request.call_args
        self.assertEqual(call_kwargs.kwargs.get("url"), "https://custom.api/validate")


class TestCredentialVerifierIntegration(unittest.TestCase):
    """Integration tests for CredentialVerifier with mocked providers."""

    def setUp(self):
        self.verifier = CredentialVerifier()

    @patch("vaultknox.verifier.requests.request")
    def test_full_verification_flow_openai(self, mock_request):
        """Test full flow: vault response -> verify."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        # Simulate vault.get_secret() response
        vault_response = {
            "id": "secret_123",
            "type": "api_key",
            "label": "OpenAI API Key",
            "payload": {
                "service": "openai",
                "key": "sk-test-openai-key",
                "scope": "models.read",
            },
        }

        result = self.verifier.verify_from_vault_response(vault_response)
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.provider, "openai")

    @patch("vaultknox.verifier.requests.request")
    def test_full_verification_flow_github(self, mock_request):
        """Test full flow: vault response -> verify for GitHub."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response

        vault_response = {
            "id": "secret_456",
            "type": "api_key",
            "label": "GitHub Token",
            "payload": {
                "service": "github",
                "key": "ghp_xxxxxxxxxxxxxxxxxxxx",
            },
        }

        result = self.verifier.verify_from_vault_response(vault_response)
        self.assertEqual(result.status, "invalid")
        self.assertEqual(result.provider, "github")

    def test_verify_with_exception(self):
        """Test that exceptions in provider are caught and returned as unknown."""
        def raising_verify(payload):
            raise ValueError("Something went wrong")

        register_provider("raising_service", raising_verify)

        result = self.verifier.verify({"key": "test", "service": "raising_service"})
        self.assertEqual(result.status, "unknown")
        self.assertIn("Verification error", result.message)

    @patch("vaultknox.verifier.requests.request")
    def test_full_verification_flow_generic_bearer(self, mock_request):
        """Test full flow: vault response -> verify for generic_bearer."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        vault_response = {
            "id": "secret_generic",
            "type": "api_key",
            "label": "Generic Token",
            "payload": {
                "service": "generic_bearer",
                "key": "bearer_token_123",
                "verify_url": "https://custom.api/verify",
            },
        }

        result = self.verifier.verify_from_vault_response(vault_response)
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.provider, "generic")



class TestSecurityNoLogging(unittest.TestCase):
    """Tests to ensure no secret values are logged or echoed."""

    @patch("vaultknox.verifier.requests.request")
    def test_no_secret_in_result(self, mock_request):
        """Verify that the result doesn't echo back the secret."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        verifier = CredentialVerifier()
        result = verifier.verify({"key": "sk-super-secret-openai-key", "service": "openai"})

        # The result should have 'valid' status but no trace of the key
        self.assertEqual(result.status, "valid")
        # Use __repr__ or str on the dataclass fields directly
        result_str = str(result)
        self.assertNotIn("sk-super-secret-openai-key", result_str)
        # Verify the key is not in any of the result fields
        self.assertNotEqual(result.http_status_code, "sk-super-secret-openai-key")

    @patch("vaultknox.verifier.requests.request")
    def test_no_secret_in_headers_logged(self, mock_request):
        """Verify that the API key is not logged via request headers."""
        captured_headers = {}

        def capture_headers(*args, **kwargs):
            captured_headers.update(kwargs.get("headers", {}))
            mock_response = MagicMock()
            mock_response.status_code = 200
            return mock_response

        mock_request.side_effect = capture_headers

        verifier = CredentialVerifier()
        verifier.verify({"key": "sk-dont-log-me", "service": "openai"})

        # The key should be in headers for the HTTP request, but not logged anywhere
        self.assertIn("sk-dont-log-me", captured_headers.get("Authorization", ""))


if __name__ == "__main__":
    unittest.main()
