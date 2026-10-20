
"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type EventRow = {
  id: number;
  timestamp: string;
  action: string;
  resource: string;
  decision: string;
  reason: string;
  ml?: {
    risk_score?: number;
    is_anomaly?: boolean;
  };
};

type Stats = {
  total: number;
  allowed: number;
  blocked: number;
  review: number;
  anomalies: number;
};

const API =
  process.env.NEXT_PUBLIC_AGENTSHIELD_API || "http://127.0.0.1:8000";

export default function Dashboard() {
  const [apiKey, setApiKey] = useState("");
  const [adminKey, setAdminKey] = useState("");
  const [action, setAction] = useState("read");
  const [resource, setResource] = useState("README.md");
  const [query, setQuery] = useState(
    "Please read the public project README."
  );
  const [stats, setStats] = useState<Stats>({
    total: 0,
    allowed: 0,
    blocked: 0,
    review: 0,
    anomalies: 0,
  });
  const [events, setEvents] = useState<EventRow[]>([]);
  const [result, setResult] = useState("Ready. Run a policy check to begin.");
  const [connection, setConnection] = useState("Connecting...");
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("ALL");

  const headers = useCallback(
    () => ({
      "X-API-Key": apiKey,
      "Content-Type": "application/json",
    }),
    [apiKey]
  );

  const refresh = useCallback(async () => {
    try {
      const [statsResponse, eventsResponse] = await Promise.all([
        fetch(`${API}/api/stats`, {
          headers: headers(),
          cache: "no-store",
        }),
        fetch(`${API}/api/events`, {
          headers: headers(),
          cache: "no-store",
        }),
      ]);

      if (!statsResponse.ok || !eventsResponse.ok) {
        throw new Error("Check your API key and backend status.");
      }

      const statsData = await statsResponse.json();
      const eventsData = await eventsResponse.json();

      setStats(statsData);
      setEvents(Array.isArray(eventsData) ? eventsData : []);
      setConnection("API connected");
    } catch {
      setConnection("API disconnected");
    }
  }, [headers]);

  useEffect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), 5000);
    return () => clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    if (!apiKey) {
      setConnection("API key required");
      return;
    }

    let ws: WebSocket;

    try {
      ws = new WebSocket(
        `${API.replace(/^http/, "ws")}/ws/events`,
        ["agentshield", apiKey]
      );

      ws.onopen = () => setConnection("Live updates connected");
      ws.onmessage = () => void refresh();
      ws.onerror = () => setConnection("Live updates unavailable");
      ws.onclose = () => setConnection("Live updates disconnected");
    } catch {
      setConnection("Live updates unavailable");
    }

    return () => ws?.close();
  }, [apiKey, refresh]);

  async function submit(path: string, body: unknown) {
    setBusy(true);
    setResult("Processing request...");

    try {
      const response = await fetch(`${API}${path}`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(body),
      });

      const text = await response.text();
      let data: unknown;

      try {
        data = JSON.parse(text);
      } catch {
        data = { message: text || "The server returned an empty response." };
      }

      setResult(
        JSON.stringify(
          {
            http_status: response.status,
            success: response.ok,
            response: data,
          },
          null,
          2
        )
      );

      await refresh();
    } catch (error) {
      setResult(
        `Request failed: ${
          error instanceof Error ? error.message : String(error)
        }\n\nCheck that the backend is running at ${API}.`
      );
    } finally {
      setBusy(false);
    }
  }

  async function clearLogs() {
    const confirmed = window.confirm(
      "Clear the audit events? This action may not be reversible."
    );

    if (!confirmed) return;

    setBusy(true);

    try {
      const response = await fetch(`${API}/api/events`, {
        method: "DELETE",
        headers: { "X-Admin-Key": adminKey },
      });

      const text = await response.text();
      setResult(
        `HTTP ${response.status}\n${text || "Empty response"}`
      );

      await refresh();
    } catch (error) {
      setResult(
        `Could not clear logs: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    } finally {
      setBusy(false);
    }
  }

  const filteredEvents = useMemo(() => {
    const term = search.trim().toLowerCase();

    return events
      .filter((event) => {
        const matchesSearch =
          !term ||
          [
            event.id,
            event.action,
            event.resource,
            event.decision,
            event.reason,
          ]
            .join(" ")
            .toLowerCase()
            .includes(term);

        const matchesDecision =
          decisionFilter === "ALL" ||
          event.decision?.toUpperCase() === decisionFilter;

        return matchesSearch && matchesDecision;
      })
      .slice(0, 100);
  }, [events, search, decisionFilter]);

  function chooseExample(
    nextAction: string,
    nextResource: string
  ) {
    setAction(nextAction);
    setResource(nextResource);
  }

  return (
    <main className="dashboard">
      <aside className="sidebar">
        <div className="brand">
          Agent<span>Shield</span>
        </div>

        <p className="sidebar-caption">SECURITY CONSOLE</p>

        <nav className="side-nav">
          <a className="nav-active" href="#overview">
            <span>◈</span> Overview
          </a>
          <a href="#policy">
            <span>⌘</span> Policy tester
          </a>
          <a href="#agent">
            <span>✳</span> AI agent
          </a>
          <a href="#audit">
            <span>▤</span> Audit events
          </a>
        </nav>

        <div className="sidebar-bottom">
          <span className="status-dot" />
          <div>
            <strong>AgentShield</strong>
            <p>Local demo environment</p>
          </div>
        </div>
      </aside>

      <div className="dashboard-content">
        <header className="top">
          <div>
            <p className="eyebrow">AI SECURITY PLATFORM</p>
            <h1>Security overview</h1>
            <p className="muted">
              Monitor tool requests, policy decisions and ML risk signals.
            </p>
          </div>

          <div className="header-actions">
            <span
              className={`connection ${
                connection.includes("connected") ? "connected" : ""
              }`}
            >
              <span className="status-dot" />
              {connection}
            </span>

            <button
              className="secondary"
              disabled={busy}
              onClick={() => void refresh()}
            >
              Refresh
            </button>
          </div>
        </header>

        <section className="metrics" id="overview">
          <div className="metric">
            <span className="metric-icon">↗</span>
            <small>Total requests</small>
            <strong>{stats.total}</strong>
            <p>Recorded requests</p>
          </div>

          <div className="metric">
            <span className="metric-icon green">✓</span>
            <small>Allowed</small>
            <strong>{stats.allowed}</strong>
            <p>Permitted by policy</p>
          </div>

          <div className="metric">
            <span className="metric-icon red">⊘</span>
            <small>Blocked</small>
            <strong>{stats.blocked}</strong>
            <p>Denied by policy</p>
          </div>

          <div className="metric">
            <span className="metric-icon amber">!</span>
            <small>Review / anomalies</small>
            <strong>{stats.review} / {stats.anomalies}</strong>
            <p>Review decisions and ML signals</p>
          </div>
        </section>

        <section className="panel" id="credentials">
          <div className="section-heading">
            <div>
              <h2>Demo credentials</h2>
              <p className="muted">
                Used by this dashboard to authenticate requests.
              </p>
            </div>
            <span className="subtle-tag">LOCAL DEMO</span>
          </div>

          <div className="columns">
            <div>
              <label htmlFor="api-key">API key</label>
              <input
                id="api-key"
                type="password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                autoComplete="off"
              />
            </div>

            <div>
              <label htmlFor="admin-key">Admin key</label>
              <input
                id="admin-key"
                type="password"
                value={adminKey}
                onChange={(event) => setAdminKey(event.target.value)}
                autoComplete="off"
              />
            </div>
          </div>

          <p className="muted security-note">
            Development credentials are for local testing only. Do not expose
            admin credentials in a public deployment.
          </p>
        </section>

        <div className="columns">
          <section className="panel" id="policy">
            <div className="section-heading">
              <div>
                <p className="eyebrow">POLICY ENGINE</p>
                <h2>Test an action</h2>
              </div>
              <span className="subtle-tag">RULE CHECK</span>
            </div>

            <label htmlFor="action">Action</label>
            <select
              id="action"
              value={action}
              onChange={(event) => setAction(event.target.value)}
            >
              <option value="read">Read</option>
              <option value="list">List</option>
              <option value="write">Write</option>
              <option value="delete">Delete</option>
              <option value="execute">Execute</option>
            </select>

            <label htmlFor="resource">Resource</label>
            <input
              id="resource"
              value={resource}
              onChange={(event) => setResource(event.target.value)}
              placeholder="Enter a resource, e.g. README.md"
            />

            <div className="example-buttons">
              <button
                type="button"
                className="secondary"
                onClick={() => chooseExample("read", "README.md")}
              >
                Public file
              </button>

              <button
                type="button"
                className="secondary"
                onClick={() => chooseExample("read", ".env")}
              >
                Sensitive file
              </button>

              <button
                type="button"
                className="secondary"
                onClick={() => chooseExample("write", "README.md")}
              >
                Write example
              </button>
            </div>

            <button
              className="primary-button"
              disabled={busy || !apiKey || !resource.trim()}
              onClick={() =>
                void submit("/api/check-action", {
                  action,
                  resource,
                  recent_requests: 1,
                })
              }
            >
              {busy ? "Processing..." : "Check policy"}
              <span>→</span>
            </button>

            <p className="muted">
              This policy-check endpoint evaluates a request; it does not
              itself execute the requested tool.
            </p>
          </section>

          <section className="panel" id="agent">
            <div className="section-heading">
              <div>
                <p className="eyebrow">LOCAL LANGUAGE MODEL</p>
                <h2>Ask the AI agent</h2>
              </div>
              <span className="subtle-tag">OLLAMA</span>
            </div>

            <label htmlFor="agent-query">Your prompt</label>
            <textarea
              id="agent-query"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Ask the local agent to read a public file..."
            />

            <button
              className="primary-button"
              disabled={busy || !apiKey || !query.trim()}
              onClick={() =>
                void submit("/api/agent/query", {
                  query,
                  recent_requests: 1,
                })
              }
            >
              {busy ? "Processing..." : "Send through security gateway"}
              <span>→</span>
            </button>

            <p className="muted">
              Requires the configured local Ollama model and a working backend.
              The result depends on your current gateway implementation.
            </p>
          </section>
        </div>

        <section className="panel" id="audit">
          <div className="section-heading">
            <div>
              <p className="eyebrow">ACTIVITY MONITOR</p>
              <h2>Audit events</h2>
              <p className="muted">
                Search recorded events and filter by policy decision.
              </p>
            </div>

            <button
              className="secondary"
              disabled={busy}
              onClick={() => void clearLogs()}
            >
              Clear logs
            </button>
          </div>

          <div className="audit-controls">
            <div className="search-field">
              <label htmlFor="event-search">Search events</label>
              <input
                id="event-search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search action, resource, reason..."
              />
            </div>

            <div className="filter-field">
              <label htmlFor="decision-filter">Decision</label>
              <select
                id="decision-filter"
                value={decisionFilter}
                onChange={(event) => setDecisionFilter(event.target.value)}
              >
                <option value="ALL">All decisions</option>
                <option value="ALLOW">Allow</option>
                <option value="BLOCK">Block</option>
                <option value="REVIEW">Review</option>
              </select>
            </div>
          </div>

          <p className="muted event-count">
            Showing {filteredEvents.length} matching events
            {events.length > 100 ? " (maximum 100 displayed)" : ""}.
          </p>

          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>Decision</th>
                  <th>ML risk</th>
                  <th>Reason</th>
                </tr>
              </thead>

              <tbody>
                {filteredEvents.length > 0 ? (
                  filteredEvents.map((event) => {
                    const decision = event.decision?.toUpperCase() || "UNKNOWN";

                    return (
                      <tr key={event.id}>
                        <td>#{event.id}</td>
                        <td>{event.action}</td>
                        <td className="resource-cell">{event.resource}</td>
                        <td>
                          <span
                            className={`decision-badge ${decision}`}
                          >
                            {decision}
                          </span>
                        </td>
                        <td>
                          {event.ml?.risk_score ?? "—"}
                          {event.ml?.is_anomaly ? " · Anomaly" : ""}
                        </td>
                        <td className="reason-cell">
                          {event.reason || "No reason provided"}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={6} className="empty-state">
                      No matching events. Try another search or filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <p className="muted security-note">
            ML risk scores are demo signals, not calibrated probabilities.
          </p>
        </section>

        <section className="panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">REQUEST DETAILS</p>
              <h2>Latest response</h2>
            </div>
            <button
              className="secondary"
              onClick={() => setResult("Ready. Run a policy check to begin.")}
            >
              Reset
            </button>
          </div>

          <pre className="result">{result}</pre>
        </section>

        <footer className="footer-note">
          <strong>AgentShield</strong>
          <span>
            Security portfolio prototype · Verify security controls before
            any production use.
          </span>
        </footer>
      </div>
    </main>
  );
}
