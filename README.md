# AgentShield — AI Agent Security Gateway (Security-Hardened Prototype)

AgentShield demonstrates a controlled security gateway for AI-agent tool requests. It combines deterministic policy enforcement, API-key authentication, path validation, SQLite audit events, and an Isolation Forest anomaly signal.

## What is implemented

- **Authentication:** `X-API-Key` protects action checks, event history, statistics, and the controlled tool-call endpoint. WebSocket clients authenticate through a subprotocol instead of a URL query string.
- **Separate admin credential:** clearing audit events requires `X-Admin-Key`.
- **Fail-closed policy:** unknown actions, malformed paths, path traversal, sensitive resource markers, and high-impact actions cannot be automatically allowed.
- **Enforcement demo:** `POST /api/tool-call` executes only the registered `read_file` and `list_public_files` demo tools after an `ALLOW` decision. `BLOCK` and `REVIEW` never execute a tool.
- **Path containment:** readable resources are resolved beneath `safe_resources/`; absolute paths and traversal are rejected.
- **Persistent audit events:** SQLite stores decisions across restarts; credentials are not written into the audit database.
- **ML anomaly signal:** Isolation Forest can escalate an otherwise allowed request to `REVIEW`; it cannot override a rule-based `BLOCK`.
- **Bounded inputs and file reads:** Pydantic input limits and a 256 KB read limit are applied.
- **Production configuration checks:** production mode refuses to start with default/weak or missing credentials and disables interactive API docs.

## Human approval workflow

A `REVIEW` decision from `POST /api/tool-call` returns HTTP 409 with an `approval_id`; the tool is not executed. An administrator can inspect the queue with `GET /api/approvals` using `X-Admin-Key`, then approve one request with `POST /api/approvals/{approval_id}/approve`. Approval is one-time, bound to the original tool/action/resource, and rechecks mandatory BLOCK rules. The demo still supports only the two sandboxed read/list tools; approval does not enable shell, write, delete, or arbitrary tool execution.

Example (development credentials only):

```powershell
$admin = @{ 'X-Admin-Key' = 'dev-admin-only-change-me' }
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/approvals -Headers $admin
# Replace 1 with the approval_id returned by a REVIEW response.
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/approvals/1/approve -Method Post -Headers $admin
```

## Important limitations — read before deployment

This is a **security-hardened portfolio prototype, not a production-certified security product**. It only demonstrates enforcement for the two local read/list tools implemented here. It does not automatically intercept external agents or every MCP tool. The ML model is trained on synthetic data, so it must not be trusted as a production detector until trained and evaluated on representative data. The in-process WebSocket registry and default request handling are single-process demo choices. Production deployments still need a reverse proxy with TLS, centralized rate limiting, secrets management, least-privilege OS/container permissions, database backup/retention controls, monitoring, threat modeling, dependency scanning, and independent security testing. Configure a persistent, access-controlled database path for deployment; SQLite may not suit multi-instance deployments.

## Run locally on Windows (PowerShell)

Open PowerShell in the extracted project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Interactive API docs are available at `http://127.0.0.1:8000/docs` in development mode.

The dashboard uses local demo credentials by default:
- API key: `dev-only-change-me`
- Admin key: `dev-admin-only-change-me`

**These default values are only for local development. Never expose them on a network.** For a local custom key, set environment variables before launching:

```powershell
$env:AGENTSHIELD_API_KEY = 'replace-with-a-long-random-secret-at-least-32-characters'
$env:AGENTSHIELD_ADMIN_API_KEY = 'use-a-different-long-random-admin-secret-at-least-32-characters'
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

When custom keys are used, enter them in the dashboard's credential fields. Do not commit real secrets or put them in screenshots or source control.

## Production-mode configuration check

Set unique secrets using a proper secret manager, configure trusted CORS origins and TLS at a reverse proxy, and then set:

```powershell
$env:AGENTSHIELD_ENV = 'production'
$env:AGENTSHIELD_API_KEY = 'your-unique-random-secret-of-at-least-32-characters'
$env:AGENTSHIELD_ADMIN_API_KEY = 'a-different-random-admin-secret-at-least-32-characters'
$env:AGENTSHIELD_CORS_ORIGINS = 'https://your-approved-dashboard.example'
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

These are configuration examples, not a complete deployment recipe. Put a TLS-terminating reverse proxy in front of the service and restrict network access to it.

## API examples (PowerShell)

```powershell
$headers = @{ 'X-API-Key' = 'dev-only-change-me' }
$body = @{ action='read'; resource='README.md'; recent_requests=1 } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/check-action -Method Post -Headers $headers -ContentType 'application/json' -Body $body

$toolBody = @{ tool='read_file'; action='read'; resource='README.md'; recent_requests=1 } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/tool-call -Method Post -Headers $headers -ContentType 'application/json' -Body $toolBody

# A sensitive file should be blocked and never executed.
$blockedBody = @{ tool='read_file'; action='read'; resource='.env'; recent_requests=1 } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/tool-call -Method Post -Headers $headers -ContentType 'application/json' -Body $blockedBody
```

Expected: reading `README.md` returns content from `safe_resources/README.md` only if the final decision is `ALLOW`. Reading `.env` returns HTTP 403; a `REVIEW` decision returns HTTP 409. Neither response executes a tool.

## Architecture

`AI agent / test client → authenticated gateway → fail-closed policy → ML anomaly signal → ALLOW / REVIEW / BLOCK → controlled read/list tool only on ALLOW → SQLite audit event → dashboard`

See [SECURITY.md](SECURITY.md) for implemented controls, remaining production work, and the responsible test boundary.

## Tests

Install requirements, then run:

```powershell
python -m pytest backend -q
```

Tests cover authentication, sensitive-file blocking, traversal and symlink rejection, approval permissions and replay prevention, and the tool execution boundary.

## Reconstructed original integrations: Ollama + MCP + Next.js

This combined package preserves the security-hardened gateway and reconstructs the original integration concepts discussed for the earlier AgentShield project. It is **not a byte-for-byte merge of your original local files** because those files were not available in this chat. Review and adapt any differences from your original implementation.

### Local Ollama agent

1. Install/start Ollama and pull the model:
   ```powershell
   ollama pull qwen2.5:3b
   ollama serve
   ```
   If Ollama is already running as a Windows service, you may not need `ollama serve`.
2. Start the AgentShield FastAPI backend as above.
3. In the dashboard, enter a prompt in **Local Ollama agent**, or call:
   ```powershell
   $headers = @{ 'X-API-Key' = 'dev-only-change-me' }
   $body = @{ query = 'Please read the public project README.' } | ConvertTo-Json
   Invoke-RestMethod -Uri http://127.0.0.1:8000/api/agent/query -Method Post -Headers $headers -ContentType 'application/json' -Body $body
   ```
The model only proposes a public-file read or no tool. Its output is untrusted and the gateway makes the final decision. If Ollama is offline or returns invalid output, no tool executes.

### MCP server adapter

Install requirements, start the gateway, then in a second PowerShell window from the project root run:

```powershell
$env:AGENTSHIELD_API_KEY = 'dev-only-change-me'
python mcp_server.py
```

The MCP server exposes `read_project_file(path)` and `list_public_files(path)`. These tools call the authenticated AgentShield gateway; they do not read arbitrary local files directly. Configure your MCP-compatible client to launch `python` with the absolute path to `mcp_server.py` as its stdio server. Keep the API key in the client's environment, not in a checked-in configuration file.

### Next.js dashboard option

The default `http://127.0.0.1:8000` dashboard remains available. An additional Next.js dashboard scaffold is in `frontend_nextjs/`:

```powershell
cd frontend_nextjs
npm install
npm run dev
```

Open `http://localhost:3000`. Set `NEXT_PUBLIC_AGENTSHIELD_API=http://127.0.0.1:8000` in `frontend_nextjs/.env.local` if needed. For local demo only, enter the development API/admin keys in the UI. Browser-exposed API keys are not a suitable production identity system; production should use a server-side authenticated session and keep privileged credentials off the client.

### Combined architecture

`Ollama or MCP client → authenticated AgentShield API → mandatory rules + ML anomaly signal → ALLOW / REVIEW / BLOCK → sandboxed read/list tool → SQLite audit log → live dashboard`

The MCP adapter and Ollama route use the same controlled gateway, but this is still a portfolio integration. Validate each MCP client configuration, threat-model the complete tool surface, and perform independent security testing before deployment. The Isolation Forest still uses synthetic bootstrap data and is not a calibrated production detector.
