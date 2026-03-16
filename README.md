# MCP Server for One Identity Safeguard for Privileged Passwords (SPP)

An MCP (Model Context Protocol) server that provides AI assistants with tools to interact with One Identity Safeguard for Privileged Passwords.

## Tools

| Tool | Description |
|------|-------------|
| `authenticate` | OAuth2 login to Safeguard SPP |
| `logout` | Invalidate session |
| `check_appliance_status` | Health check (no auth required) |
| `list_assets` / `get_asset` / `create_asset` / `delete_asset` | Manage assets |
| `list_accounts` / `get_account` / `create_account` / `delete_account` | Manage accounts |
| `create_access_request` / `get_access_request` | Access request workflow |
| `approve_access_request` / `deny_access_request` | Approve/deny requests |
| `checkout_password` | Retrieve credential from approved request |
| `checkin_access_request` | Release checked-out credential |
| `list_requestable_accounts` | Accounts you can request |
| `list_actionable_requests` | Requests you can approve/deny |
| `list_users` / `get_me` | User management |
| `list_entitlements` | View entitlements/roles |
| `list_platforms` | Available platform types |
| `list_auth_providers` | Available identity providers |
| `a2a_retrieve_credential` | A2A credential retrieval (no workflow) |

## Setup

```bash
pip install mcp httpx
```

Copy `.env.example` to `.env` and configure your appliance URL:

```bash
cp .env.example .env
# Edit .env with your values
```

## Running

### Standalone (stdio transport for Claude Code / Claude Desktop)

```bash
python3 safeguard_mcp_server.py
```

### Claude Desktop configuration

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "safeguard-spp": {
      "command": "python3",
      "args": ["/path/to/safeguard_mcp_server.py"],
      "env": {
        "SPP_APPLIANCE_URL": "https://your-safeguard-appliance",
        "SPP_VERIFY_SSL": "false"
      }
    }
  }
}
```

### Claude Code configuration

Add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "safeguard-spp": {
      "command": "python3",
      "args": ["safeguard_mcp_server.py"],
      "env": {
        "SPP_APPLIANCE_URL": "https://your-safeguard-appliance",
        "SPP_VERIFY_SSL": "false"
      }
    }
  }
}
```

## Typical Workflow

1. **Authenticate** → `authenticate(username, password)`
2. **Browse requestable accounts** → `list_requestable_accounts()`
3. **Request access** → `create_access_request(account_id, reason="...")`
4. **Check out password** → `checkout_password(request_id)`
5. **Use the credential** (externally)
6. **Check in** → `checkin_access_request(request_id)`

For automated integrations, use `a2a_retrieve_credential(api_key)` to skip the workflow.

## API Reference

Built against the [Safeguard SPP v4 REST API](https://support.oneidentity.com/technical-documents/one-identity-safeguard-for-privileged-passwords/7.4/user-guide/using-the-api).
