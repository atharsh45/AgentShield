"""Tests that the Ollama proposal endpoint never bypasses the security gateway."""
from fastapi.testclient import TestClient
import backend.main as main
from backend import audit


def test_agent_proposed_sensitive_file_is_blocked(monkeypatch, tmp_path):
    original_path = audit.DB_PATH
    audit.DB_PATH = tmp_path / "agent-audit.sqlite3"
    async def fake_proposal(_query):
        return {"tool": "read_file", "resource": ".env"}
    monkeypatch.setattr(main, "propose_action", fake_proposal)
    try:
        with TestClient(main.app) as client:
            response = client.post("/api/agent/query", headers={"X-API-Key": main.API_KEY}, json={"query": "Read .env"})
            assert response.status_code == 200
            payload = response.json()
            assert payload["decision"] == "BLOCK"
            assert payload["tool_executed"] is False
    finally:
        audit.DB_PATH = original_path


def test_agent_can_return_without_tool(monkeypatch):
    async def fake_proposal(_query):
        return {"tool": "none", "response": "No file access needed."}
    monkeypatch.setattr(main, "propose_action", fake_proposal)
    with TestClient(main.app) as client:
        response = client.post("/api/agent/query", headers={"X-API-Key": main.API_KEY}, json={"query": "Say hello"})
        assert response.status_code == 200
        assert response.json()["decision"] == "NO_TOOL"
        assert response.json()["tool_executed"] is False
