# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP (Model Context Protocol) server for **One Identity Safeguard for Privileged Passwords (SPP)**. Provides AI assistants with tools to interact with the Safeguard REST API for privileged access management.

## Architecture

Single-file Python MCP server (`safeguard_mcp_server.py`, ~1,280 lines) built on **FastMCP** with **httpx** for HTTP. No separate modules — all tools, auth, and helpers live in one file.

**Key architectural patterns:**
- In-memory token cache (`_token_cache` dict) keyed by appliance URL for session persistence across tool calls
- Two-step OAuth2 auth: RSTS token → Safeguard token exchange (both password and certificate flows)
- httpx async context manager for connection lifecycle
- All API calls go through `/service/core/{version}/` (except A2A which uses `/service/a2a/v4/`)
- OData filtering support passed through to Safeguard API

**Tool groups in order:**
1. **Authentication** (~L87-248): `authenticate`, `authenticate_certificate`, `logout`
2. **Assets** (~L273-399): CRUD for managed systems
3. **Accounts** (~L402-517): CRUD for accounts on assets
4. **Access Requests** (~L519-757): Full workflow — create, approve/deny, checkout, session init, checkin
5. **Users & Entitlements** (~L759-1123): User management, roles, access policies
6. **Platform & Status** (~L1125-1272): Platforms, auth providers, health checks

## Running the Server

```bash
python3 safeguard_mcp_server.py
```

Configured via `.mcp.json` for Claude Code integration. Key environment variables:
- `SPP_APPLIANCE_URL` (required): Safeguard appliance URL
- `SPP_VERIFY_SSL` (default: `false`): SSL cert validation
- `SPP_API_VERSION` (default: `v4`): API version
- `SPP_USERNAME`, `SPP_PASSWORD`, `SPP_PROVIDER`: Optional default credentials

## Dependencies

- `mcp` (FastMCP framework)
- `httpx` (HTTP client)

No requirements.txt — install manually: `pip install mcp httpx`

## Testing

No automated test suite exists. Testing is manual against a live Safeguard appliance.

## Custom Platforms

`custom-platforms/` contains JSON platform scripts (e.g., `SophosUTM.json`) that define CheckSystem, CheckPassword, and ChangePassword operations for non-standard devices.
