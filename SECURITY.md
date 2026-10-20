# AgentShield Security Notes

## Scope

This repository is a security-hardened learning/portfolio prototype. It is not a certified or independently audited security product. The gateway enforces policy only for its own registered local demo tools (`read_file`, `list_public_files`). It does not transparently intercept every external AI agent, operating-system action, or MCP server.

## Security controls implemented

- API-key authentication for ordinary endpoints and a separate administrator key for approval and destructive audit actions.
- Production startup rejects weak/default API keys and disables interactive API documentation.
- Fail-closed rules for unknown actions, malformed/absolute/traversal paths, sensitive-file markers, and high-impact actions.
- Explicit tool registry with only sandboxed read/list demo tools.
- Resource containment under `safe_resources/`, symbolic-link rejection, and bounded file reads.
- `BLOCK` never executes. `REVIEW` creates a pending approval and does not execute until an administrator approves it.
- Approval requests are claimed atomically and can be used only once. Mandatory `BLOCK` policies are rechecked at approval time and cannot be overridden.
- SQLite audit events and approval status survive process restarts.
- Basic HTTP security headers and bounded request fields.
- Isolation Forest is advisory only and can escalate an allow to review; it cannot override mandatory blocks.

## Remaining production work

Before real deployment, complete and document all of the following:

1. Integrate every production tool/MCP path so no protected action can bypass the gateway; run bypass tests against the actual deployment.
2. Replace shared API keys with an organization identity provider or short-lived signed credentials, per-caller roles, rotation, and revocation.
3. Put the service behind TLS, a trusted reverse proxy, and centralized rate limiting. Restrict inbound network access.
4. Use a managed database for multi-instance deployments; set backup, retention, encryption-at-rest, access-control, and tamper-evidence policies for audit logs.
5. Use OS/container sandboxing and least-privilege service accounts. For hostile concurrent filesystem changes, use OS-level safe file-open primitives rather than path checks alone.
6. Add CSRF/origin considerations if browser-based admin actions are exposed; do not expose admin credentials to untrusted clients.
7. Train and evaluate anomaly detection on representative, labelled data; report precision, recall, false positives, and false negatives. Synthetic demo data is not production evidence.
8. Add dependency scanning, SAST, DAST, fuzzing, secrets scanning, incident response, monitoring, recovery drills, and independent security review.

## Responsible test boundary

Run tests only against the local demo resources and systems you own or are explicitly authorized to test. Do not connect this prototype to production tools or sensitive data until the remaining work above has been completed and reviewed.
