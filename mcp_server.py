"""MCP adapter: all tool requests are delegated to the authenticated AgentShield API.
Run from the project root with: python mcp_server.py
"""
import json
import os
import httpx
from mcp.server.fastmcp import FastMCP

GATEWAY_URL = os.getenv("AGENTSHIELD_URL", "http://127.0.0.1:8000").rstrip("/")
API_KEY = os.getenv("AGENTSHIELD_API_KEY", "dev-only-change-me")
mcp = FastMCP("AgentShield Secure Tools")

async def _gateway_call(tool: str, action: str, resource: str) -> str:
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            f"{GATEWAY_URL}/api/tool-call",
            headers={"X-API-Key": API_KEY},
            json={"tool": tool, "action": action, "resource": resource, "recent_requests": 1},
        )
    try:
        payload = response.json()
    except ValueError:
        payload = {"message": "Gateway returned a non-JSON response."}
    if response.status_code != 200:
        detail = payload.get("detail", payload)
        return json.dumps({"executed": False, "http_status": response.status_code, "detail": detail})
    return json.dumps({"executed": True, "result": payload.get("result"), "event": payload.get("event")})

@mcp.tool()
async def read_project_file(path: str) -> str:
    """Read a public demo project file through AgentShield security enforcement."""
    return await _gateway_call("read_file", "read", path)

@mcp.tool()
async def list_public_files(path: str = "public") -> str:
    """List files in the approved public/ or docs/ sandbox directories through AgentShield."""
    return await _gateway_call("list_public_files", "list", path)

if __name__ == "__main__":
    mcp.run(transport="stdio")
