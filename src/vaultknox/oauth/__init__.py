"""OAuth support for VaultKnox.

RFC 7636 PKCE flow for OAuth2 providers (Google, GitHub, OpenAI).
Provides:
- PKCE code verifier/challenge generation
- Ephemeral callback server for redirect handling
- Token exchange and refresh
- Credential storage with refresh token handling
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger("vaultknox.oauth")

# ── PKCE - RFC 7636 ────────────────────────────────────────────────────────────────


def generate_code_verifier(length: int = 128) -> str:
    """Generate a random code verifier for PKCE.
    
    The verifier must be at least 43 characters and at most 128 characters.
    """
    if length < 43:
        length = 43
    elif length > 128:
        length = 128
    # Generate random bytes and URL-safe base64 encode
    return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode("utf-8").rstrip("=")


def generate_code_challenge(code_verifier: str) -> str:
    """Generate code challenge from verifier using S256 method.
    
    Per RFC 7636, the challenge is BASE64URL(SHA256(ASCII(code_verifier))).
    """
    # SHA256 hash of the verifier
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    # Base64 URL-safe encode without padding
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# ── CSRF State - Single-use token ───────────────────────────────────────────────────


def generate_state() -> str:
    """Generate a single-use CSRF state token."""
    return secrets.token_urlsafe(32)


def verify_state(provided: str, expected: str) -> bool:
    """Constant-time comparison of state tokens."""
    return secrets.compare_digest(provided, expected)


# ── OAuth Errors ────────────────────────────────────────────────────────────────


class OAuthError(Exception):
    """Base exception for OAuth errors."""
    pass


class OAuthTimeout(OAuthError):
    """Callback timed out."""
    pass


class OAuthDenied(OAuthError):
    """User denied authorization."""
    pass


class OAuthStateMismatch(OAuthError):
    """CSRF state mismatch."""
    pass


class OAuthTokenError(OAuthError):
    """Token exchange failed."""
    pass


# ── OAuth Providers ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class OAuthProvider:
    """OAuth provider configuration."""
    id: str
    name: str
    auth_url: str
    token_url: str
    scopes: list[str]
    default_redirect_port: int


# Default provider configurations
DEFAULT_PROVIDERS: dict[str, OAuthProvider] = {
    "google": OAuthProvider(
        id="google",
        name="Google",
        auth_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        scopes=["https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/gmail.readonly"],
        default_redirect_port=8765,
    ),
    "github": OAuthProvider(
        id="github",
        name="GitHub",
        auth_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        scopes=["user", "repo", "read:org"],
        default_redirect_port=8766,
    ),
    "openai": OAuthProvider(
        id="openai",
        name="OpenAI",
        auth_url="https://chat.openai.com/oauth/authorize",
        token_url="https://chat.openai.com/oauth/token",
        scopes=["identity"],
        default_redirect_port=8767,
    ),
}


# ── Callback Server ───────────────────────────────────────────────────────────────


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback."""
    
    def do_GET(self):
        """Handle callback GET request."""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        
        # Extract oauth params
        code = params.get("code", [None])[0]
        state = params.get("state", [None])[0]
        error = params.get("error", [None])[0]
        error_description = params.get("error_description", [None])[0]
        
        # Store in server instance
        self.server._oauth_code = code
        self.server._oauth_state = state
        self.server._oauth_error = error or error_description
        
        # Send response
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        if error:
            self.wfile.write(b"<html><body><h1>Authorization Denied</h1><p>The authorization was denied.</p></body></html>")
        else:
            self.wfile.write(b"<html><body><h1>Authorization Successful</h1><p>You may close this window.</p></body></html>")
    
    def log_message(self, format, *args):
        # Suppress access logs
        pass


class CallbackServer(HTTPServer):
    """Ephemeral OAuth callback server."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        super().__init__((host, port), CallbackHandler)
        self._oauth_code: str | None = None
        self._oauth_state: str | None = None
        self._oauth_error: str | None = None


def wait_for_callback(host: str, port: int, timeout: float = 300.0) -> tuple[str, str]:
    """Wait for OAuth callback and return (code, state).
    
    Args:
        host: Host to bind to
        port: Port (0 = auto-assign)
        timeout: Seconds to wait for callback
        
    Returns:
        Tuple of (authorization_code, state_token)
        
    Raises:
        OAuthTimeout: If callback timed out
    """
    server = CallbackServer(host, port)
    port = server.server_address[1]
    
    # Start server in background
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    
    # Wait for callback
    thread.join(timeout)
    
    if thread.is_alive():
        server.shutdown()
        raise OAuthTimeout(f"Callback timed out after {timeout}s")
    
    if server._oauth_error:
        server.shutdown()
        raise OAuthDenied(server._oauth_error)
    
    if not server._oauth_code:
        server.shutdown()
        raise OAuthError("No authorization code received")
    
    return server._oauth_code, server._oauth_state


# ── Token Exchange ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TokenResponse:
    """OAuth token response."""
    access_token: str
    token_type: str
    expires_in: int | None
    refresh_token: str | None
    scope: str | None
    issued_at: datetime


def exchange_code(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code_verifier: str,
    token_url: str,
) -> TokenResponse:
    """Exchange authorization code for tokens.
    
    Args:
        code: Authorization code from callback
        client_id: OAuth client ID
        client_secret: OAuth client secret
        redirect_uri: Redirect URI used in auth request
        code_verifier: PKCE code verifier
        token_url: Token endpoint URL
        
    Returns:
        TokenResponse with access/refresh tokens
        
    Raises:
        OAuthTokenError: If exchange fails
    """
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    
    try:
        request = Request(
            token_url,
            data=urllib.parse.urlencode(data).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except URLError as e:
        raise OAuthTokenError(f"Token exchange failed: {e}") from e
    except json.JSONDecodeError as e:
        raise OAuthTokenError(f"Invalid token response: {e}") from e
    
    if "error" in result:
        raise OAuthTokenError(f"Token error: {result.get('error_description', result.get('error'))}")
    
    return TokenResponse(
        access_token=result["access_token"],
        token_type=result.get("token_type", "Bearer"),
        expires_in=result.get("expires_in"),
        refresh_token=result.get("refresh_token"),
        scope=result.get("scope"),
        issued_at=datetime.now(timezone.utc),
    )


def refresh_access_token(
    refresh_token: str,
    client_id: str,
    client_secret: str,
    token_url: str,
) -> TokenResponse:
    """Refresh an access token using refresh token.
    
    Args:
        refresh_token: Refresh token
        client_id: OAuth client ID  
        client_secret: OAuth client secret
        token_url: Token endpoint URL
        
    Returns:
        TokenResponse with new access/refresh tokens
    """
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    }
    
    try:
        request = Request(
            token_url,
            data=urllib.parse.urlencode(data).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except URLError as e:
        raise OAuthTokenError(f"Token refresh failed: {e}") from e
    except json.JSONDecodeError as e:
        raise OAuthTokenError(f"Invalid refresh response: {e}") from e
    
    if "error" in result:
        raise OAuthTokenError(f"Refresh error: {result.get('error_description', result.get('error'))}")
    
    return TokenResponse(
        access_token=result["access_token"],
        token_type=result.get("token_type", "Bearer"),
        expires_in=result.get("expires_in"),
        refresh_token=result.get("refresh_token", refresh_token),  # May not be returned
        scope=result.get("scope"),
        issued_at=datetime.now(timezone.utc),
    )


# ── Login Flow Orchestrator ───────────────────────────────────────────────────


class LoginFlow:
    """High-level OAuth PKCE login flow."""
    
    def __init__(
        self,
        provider: OAuthProvider,
        client_id: str,
        client_secret: str,
        redirect_port: int | None = None,
    ):
        self.provider = provider
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_port = redirect_port or provider.default_redirect_port
        self.redirect_uri = f"http://127.0.0.1:{self.redirect_port}"
    
    def start(self) -> tuple[str, str]:
        """Start the auth flow and return (auth_url, state).
        
        Opens browser and starts callback server.
        """
        # Generate PKCE
        self.code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(self.code_verifier)
        self.state = generate_state()
        
        # Build auth URL
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.provider.scopes),
            "state": self.state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        auth_url = f"{self.provider.auth_url}?{urllib.parse.urlencode(params)}"
        
        return auth_url, self.state
    
    def wait_for_callback(self, timeout: float = 300.0) -> TokenResponse:
        """Wait for callback and exchange for tokens."""
        code, received_state = wait_for_callback(
            "127.0.0.1", 
            self.redirect_port, 
            timeout
        )
        
        # Verify state
        if not verify_state(received_state, self.state):
            raise OAuthStateMismatch("CSRF state mismatch")
        
        # Exchange code for tokens
        return exchange_code(
            code=code,
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri,
            code_verifier=self.code_verifier,
            token_url=self.provider.token_url,
        )


# ── Stored OAuth Secrets ──────────────────────────────────────────────────


@dataclass
class StoredOAuth:
    """Stored OAuth credential with refresh support."""
    secret_id: str
    provider_id: str
    label: str
    access_token: str
    token_type: str
    refresh_token: str | None
    expires_at: datetime | None
    scope: str
    metadata: dict[str, Any]
    
    @property
    def is_expired(self) -> bool:
        """Check if access token is expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) >= self.expires_at
    
    @property
    def needs_refresh(self) -> bool:
        """Check if token should be refreshed (5 min buffer)."""
        if not self.expires_at:
            return False
        buffer = timedelta(minutes=5)
        return datetime.now(timezone.utc) + buffer >= self.expires_at
    
    def to_payload(self) -> dict[str, Any]:
        """Convert to vault payload format."""
        return {
            "provider_id": self.provider_id,
            "access_token": self.access_token,
            "token_type": self.token_type,
            "refresh_token": self.refresh_token or "",
            "expires_at": self.expires_at.isoformat() if self.expires_at else "",
            "scope": self.scope,
            **self.metadata,
        }
    
    @classmethod
    def from_payload(cls, secret_id: str, label: str, payload: dict[str, Any]) -> "StoredOAuth":
        """Create from vault payload."""
        return cls(
            secret_id=secret_id,
            provider_id=payload.get("provider_id", ""),
            label=label,
            access_token=payload.get("access_token", ""),
            token_type=payload.get("token_type", "Bearer"),
            refresh_token=payload.get("refresh_token") or None,
            expires_at=datetime.fromisoformat(payload["expires_at"]) if payload.get("expires_at") else None,
            scope=payload.get("scope", ""),
            metadata={k: v for k, v in payload.items() 
                     if k not in ("provider_id", "access_token", "token_type", "refresh_token", "expires_at", "scope")},
        )


# ── CLI Integration ────────────────────────────────────────────────────────


def oauth_login(
    provider_id: str,
    client_id: str,
    client_secret: str,
    alias: str = "default",
    port: int | None = None,
    timeout: float = 300.0,
    open_browser: bool = True,
) -> StoredOAuth:
    """Complete OAuth login flow and return stored credential.
    
    Args:
        provider_id: Provider ID (google, github, openai)
        client_id: OAuth client ID
        client_secret: OAuth client secret  
        alias: Credential alias
        port: Redirect port (0 = auto)
        timeout: Callback timeout
        open_browser: Open browser automatically
        
    Returns:
        StoredOAuth credential ready for storage
    """
    if provider_id not in DEFAULT_PROVIDERS:
        raise OAuthError(f"Unknown provider: {provider_id}. Use: {list(DEFAULT_PROVIDERS.keys())}")
    
    provider = DEFAULT_PROVIDERS[provider_id]
    flow = LoginFlow(provider, client_id, client_secret, port)
    
    # Generate secret ID
    import uuid
    secret_id = f"oauth_{provider_id}_{alias}_{uuid.uuid4().hex[:8]}"
    
    # Start auth flow
    auth_url, state = flow.start()
    
    if open_browser:
        webbrowser.open(auth_url)
        print(f"Opened: {auth_url}")
        print("Please authorize in your browser...")
    else:
        print(f"Visit this URL to authorize:")
        print(auth_url)
    
    # Wait for callback
    token_response = flow.wait_for_callback(timeout)
    
    # Calculate expiry
    expires_at = None
    if token_response.expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=token_response.expires_in)
    
    return StoredOAuth(
        secret_id=secret_id,
        provider_id=provider_id,
        label=f"{provider.name} OAuth ({alias})",
        access_token=token_response.access_token,
        token_type=token_response.token_type,
        refresh_token=token_response.refresh_token,
        expires_at=expires_at,
        scope=token_response.scope or "",
        metadata={"client_id": client_id},
    )