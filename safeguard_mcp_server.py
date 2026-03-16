#!/usr/bin/env python3
"""
MCP Server for One Identity Safeguard for Privileged Passwords (SPP).

Exposes Safeguard SPP operations as MCP tools for AI assistants:
  - Authentication (RSTS OAuth2 + token exchange)
  - Asset management (CRUD)
  - Account management (CRUD)
  - Access request workflow (create, approve, deny, check-in)
  - Password checkout (retrieve credentials)
  - User management
  - A2A credential retrieval
"""

import json
import logging
import os
import ssl
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration – reads from environment variables
# ---------------------------------------------------------------------------
SPP_APPLIANCE_URL = os.environ.get("SPP_APPLIANCE_URL", "")  # e.g. https://10.0.0.1
SPP_VERIFY_SSL = os.environ.get("SPP_VERIFY_SSL", "false").lower() == "true"
SPP_API_VERSION = os.environ.get("SPP_API_VERSION", "v4")

# Optional default credentials (can be overridden per-call)
SPP_USERNAME = os.environ.get("SPP_USERNAME", "")
SPP_PASSWORD = os.environ.get("SPP_PASSWORD", "")
SPP_PROVIDER = os.environ.get("SPP_PROVIDER", "local")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("safeguard-mcp")

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "safeguard-spp",
    instructions="One Identity Safeguard for Privileged Passwords – MCP Server",
)

# In-memory token cache (per appliance URL)
_token_cache: dict[str, str] = {}


def _http_client(
    appliance_url: str | None = None,
    cert_path: str | None = None,
    key_path: str | None = None,
) -> httpx.Client:
    """Create an httpx client with appropriate SSL and optional cert settings."""
    base = (appliance_url or SPP_APPLIANCE_URL).rstrip("/")
    kwargs: dict[str, Any] = {
        "base_url": base,
        "verify": SPP_VERIFY_SSL,
        "timeout": 30.0,
    }
    if cert_path and key_path:
        kwargs["cert"] = (cert_path, key_path)
    elif cert_path:
        kwargs["cert"] = cert_path
    return httpx.Client(**kwargs)


def _ensure_appliance(appliance_url: str | None) -> str:
    url = (appliance_url or SPP_APPLIANCE_URL).rstrip("/")
    if not url:
        raise ValueError(
            "No appliance URL configured. Set SPP_APPLIANCE_URL or pass appliance_url."
        )
    return url


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


# ===================================================================
# TOOL: authenticate
# ===================================================================
@mcp.tool()
def authenticate(
    username: str = "",
    password: str = "",
    provider: str = "",
    appliance_url: str = "",
) -> str:
    """
    Authenticate to One Identity Safeguard SPP and obtain a user token.

    Uses the RSTS OAuth2 resource-owner password flow, then exchanges the
    STS access token for a Safeguard user token.

    Args:
        username:      SPP username (defaults to SPP_USERNAME env var)
        password:      SPP password (defaults to SPP_PASSWORD env var)
        provider:      Identity provider id (defaults to SPP_PROVIDER / "local")
        appliance_url: Appliance base URL (defaults to SPP_APPLIANCE_URL env var)

    Returns:
        JSON with the user token on success.
    """
    base = _ensure_appliance(appliance_url)
    user = username or SPP_USERNAME
    pwd = password or SPP_PASSWORD
    prov = provider or SPP_PROVIDER

    if not user or not pwd:
        return json.dumps({"error": "username and password are required"})

    with _http_client(base) as client:
        # Step 1 – RSTS token
        rsts_resp = client.post(
            "/RSTS/oauth2/token",
            json={
                "grant_type": "password",
                "username": user,
                "password": pwd,
                "scope": f"rsts:sts:primaryproviderid:{prov}",
            },
        )
        if rsts_resp.status_code != 200:
            return json.dumps({
                "error": "RSTS authentication failed",
                "status": rsts_resp.status_code,
                "detail": rsts_resp.text,
            })

        sts_token = rsts_resp.json().get("access_token")
        if not sts_token:
            return json.dumps({"error": "No access_token in RSTS response"})

        # Step 2 – Exchange for Safeguard user token
        login_resp = client.post(
            f"/service/core/{SPP_API_VERSION}/Token/LoginResponse",
            json={"StsAccessToken": sts_token},
        )
        if login_resp.status_code != 200:
            return json.dumps({
                "error": "Token exchange failed",
                "status": login_resp.status_code,
                "detail": login_resp.text,
            })

        user_token = login_resp.json().get("UserToken")
        if not user_token:
            return json.dumps({"error": "No UserToken in login response"})

        _token_cache[base] = user_token
        return json.dumps({"status": "authenticated", "appliance": base})


# ===================================================================
# TOOL: authenticate_certificate
# ===================================================================
@mcp.tool()
def authenticate_certificate(
    cert_path: str,
    key_path: str = "",
    appliance_url: str = "",
) -> str:
    """
    Authenticate to Safeguard SPP using a client certificate.

    Uses the RSTS OAuth2 client_credentials flow with a TLS client
    certificate, then exchanges the STS token for a Safeguard user token.

    Args:
        cert_path:     Path to the PEM certificate file
        key_path:      Path to the PEM private key file (if separate from cert)
        appliance_url: Appliance base URL (defaults to SPP_APPLIANCE_URL env var)

    Returns:
        JSON with authentication status and authenticated user on success.
    """
    base = _ensure_appliance(appliance_url)

    if not cert_path:
        return json.dumps({"error": "cert_path is required"})

    with _http_client(base, cert_path=cert_path, key_path=key_path or None) as client:
        # Step 1 – RSTS token via client certificate
        rsts_resp = client.post(
            "/RSTS/oauth2/token",
            json={
                "grant_type": "client_credentials",
                "scope": "rsts:sts:primaryproviderid:certificate",
            },
        )
        if rsts_resp.status_code != 200:
            return json.dumps({
                "error": "RSTS certificate authentication failed",
                "status": rsts_resp.status_code,
                "detail": rsts_resp.text,
            })

        sts_token = rsts_resp.json().get("access_token")
        if not sts_token:
            return json.dumps({"error": "No access_token in RSTS response"})

        # Step 2 – Exchange for Safeguard user token
        login_resp = client.post(
            f"/service/core/{SPP_API_VERSION}/Token/LoginResponse",
            json={"StsAccessToken": sts_token},
        )
        if login_resp.status_code != 200:
            return json.dumps({
                "error": "Token exchange failed",
                "status": login_resp.status_code,
                "detail": login_resp.text,
            })

        user_token = login_resp.json().get("UserToken")
        if not user_token:
            return json.dumps({"error": "No UserToken in login response"})

        _token_cache[base] = user_token

        # Get authenticated user identity
        me_resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Me",
            headers=_headers(user_token),
        )
        user_info = {}
        if me_resp.status_code == 200:
            me = me_resp.json()
            user_info = {"user": me.get("DisplayName"), "user_id": me.get("Id")}

        return json.dumps({"status": "authenticated", "appliance": base, **user_info})


def _get_token(appliance_url: str | None = None) -> str:
    base = _ensure_appliance(appliance_url)
    token = _token_cache.get(base)
    if not token:
        raise ValueError(
            "Not authenticated. Call the 'authenticate' tool first."
        )
    return token


# ===================================================================
# TOOL: logout
# ===================================================================
@mcp.tool()
def logout(appliance_url: str = "") -> str:
    """
    Log out from Safeguard SPP and invalidate the cached token.

    Args:
        appliance_url: Appliance base URL (defaults to SPP_APPLIANCE_URL)
    """
    base = _ensure_appliance(appliance_url)
    token = _token_cache.pop(base, None)
    if token:
        with _http_client(base) as client:
            client.post(
                f"/service/core/{SPP_API_VERSION}/Token/Logout",
                headers=_headers(token),
            )
    return json.dumps({"status": "logged_out", "appliance": base})


# ===================================================================
# TOOL: list_assets
# ===================================================================
@mcp.tool()
def list_assets(
    filter: str = "",
    fields: str = "",
    order_by: str = "",
    page: int = 0,
    page_size: int = 50,
    appliance_url: str = "",
) -> str:
    """
    List managed assets (servers, network devices, etc.) in Safeguard.

    Args:
        filter:        OData-style filter expression (e.g. "Name contains 'prod'")
        fields:        Comma-separated list of fields to return
        order_by:      Sort expression (e.g. "Name asc")
        page:          Page number (0-based)
        page_size:     Number of results per page
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    params: dict[str, Any] = {"page": page, "limit": page_size}
    if filter:
        params["filter"] = filter
    if fields:
        params["fields"] = fields
    if order_by:
        params["orderby"] = order_by

    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Assets",
            headers=_headers(token),
            params=params,
        )
        return resp.text


# ===================================================================
# TOOL: get_asset
# ===================================================================
@mcp.tool()
def get_asset(asset_id: int, appliance_url: str = "") -> str:
    """
    Get details for a specific asset by ID.

    Args:
        asset_id:      The asset ID
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Assets/{asset_id}",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# TOOL: create_asset
# ===================================================================
@mcp.tool()
def create_asset(
    name: str,
    network_address: str,
    platform_id: int = 0,
    description: str = "",
    appliance_url: str = "",
) -> str:
    """
    Create a new managed asset in Safeguard.

    Args:
        name:            Display name of the asset
        network_address: IP or hostname
        platform_id:     Platform type ID (use list_platforms to find)
        description:     Optional description
        appliance_url:   Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    body: dict[str, Any] = {
        "Name": name,
        "NetworkAddress": network_address,
    }
    if platform_id:
        body["PlatformId"] = platform_id
    if description:
        body["Description"] = description

    with _http_client(base) as client:
        resp = client.post(
            f"/service/core/{SPP_API_VERSION}/Assets",
            headers=_headers(token),
            json=body,
        )
        return resp.text


# ===================================================================
# TOOL: delete_asset
# ===================================================================
@mcp.tool()
def delete_asset(asset_id: int, appliance_url: str = "") -> str:
    """
    Delete an asset by ID.

    Args:
        asset_id:      The asset ID to delete
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.delete(
            f"/service/core/{SPP_API_VERSION}/Assets/{asset_id}",
            headers=_headers(token),
        )
        if resp.status_code == 204:
            return json.dumps({"status": "deleted", "asset_id": asset_id})
        return resp.text


# ===================================================================
# TOOL: list_accounts
# ===================================================================
@mcp.tool()
def list_accounts(
    filter: str = "",
    page: int = 0,
    page_size: int = 50,
    appliance_url: str = "",
) -> str:
    """
    List managed accounts across all assets.

    Args:
        filter:        OData filter (e.g. "Name eq 'root'")
        page:          Page number
        page_size:     Results per page
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    params: dict[str, Any] = {"page": page, "limit": page_size}
    if filter:
        params["filter"] = filter

    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/AssetAccounts",
            headers=_headers(token),
            params=params,
        )
        return resp.text


# ===================================================================
# TOOL: get_account
# ===================================================================
@mcp.tool()
def get_account(account_id: int, appliance_url: str = "") -> str:
    """
    Get details for a specific managed account.

    Args:
        account_id:    The account ID
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/AssetAccounts/{account_id}",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# TOOL: create_account
# ===================================================================
@mcp.tool()
def create_account(
    asset_id: int,
    name: str,
    description: str = "",
    appliance_url: str = "",
) -> str:
    """
    Create a managed account on an asset.

    Args:
        asset_id:      The parent asset ID
        name:          Account name (e.g. "root", "Administrator")
        description:   Optional description
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    body: dict[str, Any] = {
        "AssetId": asset_id,
        "Name": name,
    }
    if description:
        body["Description"] = description

    with _http_client(base) as client:
        resp = client.post(
            f"/service/core/{SPP_API_VERSION}/AssetAccounts",
            headers=_headers(token),
            json=body,
        )
        return resp.text


# ===================================================================
# TOOL: delete_account
# ===================================================================
@mcp.tool()
def delete_account(account_id: int, appliance_url: str = "") -> str:
    """
    Delete a managed account.

    Args:
        account_id:    The account ID to delete
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.delete(
            f"/service/core/{SPP_API_VERSION}/AssetAccounts/{account_id}",
            headers=_headers(token),
        )
        if resp.status_code == 204:
            return json.dumps({"status": "deleted", "account_id": account_id})
        return resp.text


# ===================================================================
# TOOL: list_access_requests
# ===================================================================
@mcp.tool()
def list_access_requests(
    filter: str = "",
    page: int = 0,
    page_size: int = 50,
    appliance_url: str = "",
) -> str:
    """
    List access requests (password checkout requests).

    Args:
        filter:        OData filter
        page:          Page number
        page_size:     Results per page
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    params: dict[str, Any] = {"page": page, "limit": page_size}
    if filter:
        params["filter"] = filter

    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/AccessRequests",
            headers=_headers(token),
            params=params,
        )
        return resp.text


# ===================================================================
# TOOL: create_access_request
# ===================================================================
@mcp.tool()
def create_access_request(
    account_id: int,
    access_request_type: str = "Password",
    reason: str = "",
    appliance_url: str = "",
) -> str:
    """
    Create a new access request (password/SSH key checkout request).

    This initiates the approval workflow. Depending on policy, the request
    may be auto-approved or require manual approval.

    Args:
        account_id:          The account to request access for
        access_request_type: "Password", "SSH", or "RemoteDesktop"
        reason:              Business justification
        appliance_url:       Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    body: dict[str, Any] = {
        "AccountId": account_id,
        "AccessRequestType": access_request_type,
    }
    if reason:
        body["ReasonComment"] = reason

    with _http_client(base) as client:
        resp = client.post(
            f"/service/core/{SPP_API_VERSION}/AccessRequests",
            headers=_headers(token),
            json=body,
        )
        return resp.text


# ===================================================================
# TOOL: get_access_request
# ===================================================================
@mcp.tool()
def get_access_request(request_id: str, appliance_url: str = "") -> str:
    """
    Get the status and details of a specific access request.

    Args:
        request_id:    The access request ID
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/AccessRequests/{request_id}",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# TOOL: approve_access_request
# ===================================================================
@mcp.tool()
def approve_access_request(
    request_id: str,
    comment: str = "",
    appliance_url: str = "",
) -> str:
    """
    Approve a pending access request.

    Args:
        request_id:    The access request ID
        comment:       Optional approval comment
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    body: dict[str, Any] = {}
    if comment:
        body["Comment"] = comment

    with _http_client(base) as client:
        resp = client.post(
            f"/service/core/{SPP_API_VERSION}/AccessRequests/{request_id}/Approve",
            headers=_headers(token),
            json=body,
        )
        return resp.text


# ===================================================================
# TOOL: deny_access_request
# ===================================================================
@mcp.tool()
def deny_access_request(
    request_id: str,
    comment: str = "",
    appliance_url: str = "",
) -> str:
    """
    Deny a pending access request.

    Args:
        request_id:    The access request ID
        comment:       Denial reason
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    body: dict[str, Any] = {}
    if comment:
        body["Comment"] = comment

    with _http_client(base) as client:
        resp = client.post(
            f"/service/core/{SPP_API_VERSION}/AccessRequests/{request_id}/Deny",
            headers=_headers(token),
            json=body,
        )
        return resp.text


# ===================================================================
# TOOL: checkout_password
# ===================================================================
@mcp.tool()
def checkout_password(request_id: str, appliance_url: str = "") -> str:
    """
    Retrieve the password for an approved access request.

    The request must be in an approved/available state. Returns the
    credential value.

    Args:
        request_id:    The access request ID (must be approved)
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.post(
            f"/service/core/{SPP_API_VERSION}/AccessRequests/{request_id}/CheckOutPassword",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# TOOL: initialize_session
# ===================================================================
@mcp.tool()
def initialize_session(request_id: str, appliance_url: str = "") -> str:
    """
    Initialize a session for an approved SSH or RDP access request.

    Returns connection details including the SSH/RDP connection string,
    session token, proxy address, and port needed to connect through SPS.

    Args:
        request_id:    The access request ID (must be in RequestAvailable state)
        appliance_url: Appliance base URL

    Returns:
        JSON with SshConnectionString, SshConnectionPort, RdpConnectionString,
        ConnectionUri, SessionId, and Token.
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.post(
            f"/service/core/{SPP_API_VERSION}/AccessRequests/{request_id}/InitializeSession",
            headers=_headers(token),
            json={},
        )
        return resp.text


# ===================================================================
# TOOL: checkin_access_request
# ===================================================================
@mcp.tool()
def checkin_access_request(request_id: str, appliance_url: str = "") -> str:
    """
    Check in (release) a previously checked-out access request.

    This signals that the credential is no longer needed, triggering
    password rotation if configured.

    Args:
        request_id:    The access request ID
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.post(
            f"/service/core/{SPP_API_VERSION}/AccessRequests/{request_id}/CheckIn",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# TOOL: create_user
# ===================================================================
@mcp.tool()
def create_user(
    name: str,
    password: str,
    first_name: str = "",
    last_name: str = "",
    description: str = "",
    email: str = "",
    auth_provider_name: str = "Local",
    auth_provider_id: int = -1,
    appliance_url: str = "",
) -> str:
    """
    Create a new local user in Safeguard SPP.

    Args:
        name:               Login name for the user
        password:           Initial password
        first_name:         Optional first name
        last_name:          Optional last name
        description:        Optional description
        email:              Optional email address
        auth_provider_name: Authentication provider name (default "Local")
        auth_provider_id:   Authentication provider ID (default -1 for Local)
        appliance_url:      Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    body: dict[str, Any] = {
        "Name": name,
        "Password": password,
        "PrimaryAuthenticationProvider": {
            "Id": auth_provider_id,
            "Name": auth_provider_name,
        },
    }
    if first_name:
        body["FirstName"] = first_name
    if last_name:
        body["LastName"] = last_name
    if description:
        body["Description"] = description
    if email:
        body["EmailAddress"] = email

    with _http_client(base) as client:
        resp = client.post(
            f"/service/core/{SPP_API_VERSION}/Users",
            headers=_headers(token),
            json=body,
        )
        return resp.text


# ===================================================================
# TOOL: delete_user
# ===================================================================
@mcp.tool()
def delete_user(user_id: int, appliance_url: str = "") -> str:
    """
    Delete a user from Safeguard SPP.

    Args:
        user_id:       The user ID to delete
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.delete(
            f"/service/core/{SPP_API_VERSION}/Users/{user_id}",
            headers=_headers(token),
        )
        if resp.status_code == 204:
            return json.dumps({"status": "deleted", "user_id": user_id})
        return resp.text


# ===================================================================
# TOOL: list_users
# ===================================================================
@mcp.tool()
def list_users(
    filter: str = "",
    page: int = 0,
    page_size: int = 50,
    appliance_url: str = "",
) -> str:
    """
    List Safeguard users.

    Args:
        filter:        OData filter
        page:          Page number
        page_size:     Results per page
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    params: dict[str, Any] = {"page": page, "limit": page_size}
    if filter:
        params["filter"] = filter

    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Users",
            headers=_headers(token),
            params=params,
        )
        return resp.text


# ===================================================================
# TOOL: get_me
# ===================================================================
@mcp.tool()
def get_me(appliance_url: str = "") -> str:
    """
    Get the currently authenticated user's profile.

    Args:
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Me",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# TOOL: list_entitlements
# ===================================================================
@mcp.tool()
def list_entitlements(
    filter: str = "",
    page: int = 0,
    page_size: int = 50,
    appliance_url: str = "",
) -> str:
    """
    List entitlements (access policies binding users to accounts).

    Args:
        filter:        OData filter
        page:          Page number
        page_size:     Results per page
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    params: dict[str, Any] = {"page": page, "limit": page_size}
    if filter:
        params["filter"] = filter

    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Roles",
            headers=_headers(token),
            params=params,
        )
        return resp.text


# ===================================================================
# TOOL: add_role_member
# ===================================================================
@mcp.tool()
def add_role_member(
    role_id: int,
    user_id: int,
    appliance_url: str = "",
) -> str:
    """
    Add a user to an entitlement (role) without removing existing members.

    First fetches the current member list, appends the new user, then
    updates the role. Use list_entitlements to find role IDs and
    list_users to find user IDs.

    Args:
        role_id:       The entitlement/role ID
        user_id:       The user ID to add
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        # Get current members
        get_resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Roles/{role_id}/Members",
            headers=_headers(token),
        )
        if get_resp.status_code != 200:
            return get_resp.text

        current_members = [{"Id": m["Id"]} for m in get_resp.json()]
        if any(m["Id"] == user_id for m in current_members):
            return json.dumps({"status": "already_member", "role_id": role_id, "user_id": user_id})

        current_members.append({"Id": user_id})

        # Update with full member list
        put_resp = client.put(
            f"/service/core/{SPP_API_VERSION}/Roles/{role_id}/Members",
            headers=_headers(token),
            json=current_members,
        )
        return put_resp.text


# ===================================================================
# TOOL: list_platforms
# ===================================================================
@mcp.tool()
def list_platforms(appliance_url: str = "") -> str:
    """
    List available platform types (Windows, Linux, etc.) for asset creation.

    Args:
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Platforms",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# TOOL: list_actionable_requests
# ===================================================================
@mcp.tool()
def list_actionable_requests(appliance_url: str = "") -> str:
    """
    List access requests that the current user can act on (approve/deny).

    Args:
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Me/ActionableRequests",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# TOOL: list_requestable_accounts
# ===================================================================
@mcp.tool()
def list_requestable_accounts(appliance_url: str = "") -> str:
    """
    List accounts that the current user is entitled to request access for.

    Args:
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/Me/RequestEntitlements",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# TOOL: a2a_retrieve_credential
# ===================================================================
@mcp.tool()
def a2a_retrieve_credential(
    api_key: str,
    asset_name: str = "",
    account_name: str = "",
    credential_type: str = "Password",
    appliance_url: str = "",
) -> str:
    """
    Retrieve a credential via the A2A (Application-to-Application) API.

    This bypasses the access-request workflow and is used for automated
    integrations. Requires a pre-configured A2A registration and API key.

    Args:
        api_key:         A2A API key (from A2A registration)
        asset_name:      Filter by asset name
        account_name:    Filter by account name
        credential_type: "Password" or "SSHKey"
        appliance_url:   Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    headers = {
        "Authorization": f"A2A {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    params: dict[str, str] = {"type": credential_type}
    if asset_name:
        params["assetName"] = asset_name
    if account_name:
        params["accountName"] = account_name

    with _http_client(base) as client:
        resp = client.get(
            "/service/a2a/v4/Credentials",
            headers=headers,
            params=params,
        )
        return resp.text


# ===================================================================
# TOOL: check_appliance_status
# ===================================================================
@mcp.tool()
def check_appliance_status(appliance_url: str = "") -> str:
    """
    Check the health/availability status of the Safeguard appliance.
    Does not require authentication.

    Args:
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    with _http_client(base) as client:
        resp = client.get(
            f"/service/appliance/{SPP_API_VERSION}/ApplianceStatus",
        )
        return resp.text


# ===================================================================
# TOOL: list_auth_providers
# ===================================================================
@mcp.tool()
def list_auth_providers(appliance_url: str = "") -> str:
    """
    List available authentication providers (local, AD, LDAP, etc.).
    Useful for determining the correct provider scope for authentication.

    Args:
        appliance_url: Appliance base URL
    """
    base = _ensure_appliance(appliance_url)
    token = _get_token(appliance_url)
    with _http_client(base) as client:
        resp = client.get(
            f"/service/core/{SPP_API_VERSION}/AuthenticationProviders",
            headers=_headers(token),
        )
        return resp.text


# ===================================================================
# Entry point
# ===================================================================
if __name__ == "__main__":
    mcp.run()
