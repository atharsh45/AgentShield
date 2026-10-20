"""Security regression tests for the gateway prototype."""
import os
from fastapi.testclient import TestClient

from backend import audit
from backend.main import app, API_KEY, ADMIN_KEY
from backend.security import evaluate_rules, normalize_resource


def test_path_traversal_and_absolute_paths_fail_closed():
    assert normalize_resource('../.env') is None
    assert normalize_resource(r'..\\secret.txt') is None
    assert normalize_resource('/etc/passwd') is None
    assert evaluate_rules('read', '../safe_resources/README.md')[0] == 'BLOCK'


def test_sensitive_file_is_blocked():
    decision, _ = evaluate_rules('read', '.env')
    assert decision == 'BLOCK'


def test_unknown_action_is_blocked():
    assert evaluate_rules('launch_nuclear_submarine', 'README.md')[0] == 'BLOCK'


def test_api_requires_key_and_tool_never_executes_blocked_request(tmp_path):
    original_path = audit.DB_PATH
    audit.DB_PATH = tmp_path / 'audit.sqlite3'
    try:
        with TestClient(app) as client:
            unauthenticated = client.get('/api/events')
            assert unauthenticated.status_code == 401

            blocked = client.post('/api/tool-call', headers={'X-API-Key': API_KEY}, json={
                'tool': 'read_file', 'action': 'read', 'resource': '.env', 'recent_requests': 1
            })
            assert blocked.status_code == 403
            assert blocked.json()['detail']['message'] == 'Tool was not executed.'

            events = client.get('/api/events', headers={'X-API-Key': API_KEY})
            assert events.status_code == 200
            assert events.json()[0]['decision'] == 'BLOCK'

            no_admin = client.delete('/api/events', headers={'X-API-Key': API_KEY})
            assert no_admin.status_code == 403
            with_admin = client.delete('/api/events', headers={'X-Admin-Key': ADMIN_KEY})
            assert with_admin.status_code == 200
    finally:
        audit.DB_PATH = original_path


def test_approved_tool_reads_only_sandbox_file(tmp_path):
    original_path = audit.DB_PATH
    audit.DB_PATH = tmp_path / 'audit.sqlite3'
    try:
        with TestClient(app) as client:
            response = client.post('/api/tool-call', headers={'X-API-Key': API_KEY}, json={
                'tool': 'read_file', 'action': 'read', 'resource': 'README.md', 'recent_requests': 1
            })
            # ML may conservatively escalate the request to REVIEW; if allowed, the
            # returned content must come from the isolated safe_resources directory.
            if response.status_code == 200:
                body = response.json()
                assert body['tool_executed'] is True
                assert 'isolated' in body['result']['content'].lower()
            else:
                assert response.status_code in (409, 403)
                assert response.json()['detail']['message'] == 'Tool was not executed.'
    finally:
        audit.DB_PATH = original_path


def test_review_requires_admin_approval_and_cannot_be_replayed(tmp_path):
    original_path = audit.DB_PATH
    audit.DB_PATH = tmp_path / 'audit.sqlite3'
    try:
        # This file is inside the sandbox but is not on the automatic allowlist.
        safe_file = __import__('pathlib').Path(__file__).resolve().parent.parent / 'safe_resources' / 'review-only.txt'
        safe_file.write_text('Controlled review test file.', encoding='utf-8')
        try:
            with TestClient(app) as client:
                headers = {'X-API-Key': API_KEY}
                response = client.post('/api/tool-call', headers=headers, json={
                    'tool': 'read_file', 'action': 'read', 'resource': 'review-only.txt', 'recent_requests': 1
                })
                assert response.status_code == 409
                detail = response.json()['detail']
                assert detail['message'].startswith('Tool was not executed')
                approval_id = detail['approval_id']

                # Ordinary callers cannot inspect or approve the queue.
                assert client.get('/api/approvals', headers=headers).status_code == 403
                assert client.post(f'/api/approvals/{approval_id}/approve', headers=headers).status_code == 403

                admin = {'X-Admin-Key': ADMIN_KEY}
                queue = client.get('/api/approvals', headers=admin)
                assert queue.status_code == 200
                assert any(item['id'] == approval_id and item['status'] == 'PENDING' for item in queue.json())

                approved = client.post(f'/api/approvals/{approval_id}/approve', headers=admin)
                assert approved.status_code == 200
                assert approved.json()['tool_executed'] is True
                assert approved.json()['status'] == 'EXECUTED'

                # One-time approval prevents replay/double execution.
                replay = client.post(f'/api/approvals/{approval_id}/approve', headers=admin)
                assert replay.status_code == 404
        finally:
            safe_file.unlink(missing_ok=True)
    finally:
        audit.DB_PATH = original_path


def test_symlink_cannot_escape_sandbox(tmp_path):
    from pathlib import Path
    from fastapi import HTTPException
    from backend.main import safe_resource_path, SAFE_ROOT
    outside = tmp_path / 'outside.txt'
    outside.write_text('do not expose', encoding='utf-8')
    link = SAFE_ROOT / 'docs' / 'link-outside-test.txt'
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        # Some Windows setups require elevated privileges for symlink creation.
        return
    try:
        try:
            safe_resource_path('docs/link-outside-test.txt')
            assert False, 'symlink should have been rejected'
        except HTTPException as exc:
            assert exc.status_code == 403
    finally:
        link.unlink(missing_ok=True)
