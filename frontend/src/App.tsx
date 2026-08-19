import { useEffect, useMemo, useState } from "react";
import { ApiError, VulnHunterApi } from "./api/client";
import type {
  Assessment,
  AssessmentEvent,
  MePayload,
  ReadinessPayload,
} from "./api/types";
import {
  AssessmentEventsStream,
  type RealtimeState,
} from "./realtime/assessmentEvents";
import "./styles.css";

const api = new VulnHunterApi();
const terminalStates = new Set([
  "completed",
  "failed",
  "cancelled",
  "blocked",
  "denied",
  "timed_out",
  "readiness_blocked",
  "execution_blocked",
]);

function formatDate(value?: string): string {
  if (!value) return "Unknown time";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleString();
}

function eventLabel(event: AssessmentEvent): string {
  return event.summary || event.detail || event.type || "Persisted assessment event";
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readinessFromError(error: unknown): ReadinessPayload | null {
  if (error instanceof ApiError && isObject(error.payload)) {
    return error.payload as ReadinessPayload;
  }
  return null;
}

function mergeEvents(existing: AssessmentEvent[], incoming: AssessmentEvent[]): AssessmentEvent[] {
  const bySequence = new Map<number, AssessmentEvent>();
  for (const event of [...existing, ...incoming]) {
    if (Number.isInteger(event.sequence) && event.sequence >= 0) {
      bySequence.set(event.sequence, event);
    }
  }
  return [...bySequence.values()].sort((left, right) => left.sequence - right.sequence);
}

function statusClass(state: string): string {
  if (terminalStates.has(state)) return "status status-terminal";
  if (state === "executing" || state === "running") return "status status-running";
  if (state === "blocked" || state === "readiness_blocked") return "status status-blocked";
  return "status";
}

function LoginRequired() {
  return (
    <main className="centered-state">
      <div className="state-card">
        <p className="eyebrow">VULNHUNTER CONTROL PLANE</p>
        <h1>Sign in to open the workspace</h1>
        <p>
          This client uses the Django session and CSRF boundary. It does not create or store a
          parallel browser token.
        </p>
        <a className="primary-button" href="/login/?next=/frontend/">
          Continue to governed sign-in
        </a>
      </div>
    </main>
  );
}

function App() {
  const [me, setMe] = useState<MePayload | null>(null);
  const [readiness, setReadiness] = useState<ReadinessPayload | null>(null);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Assessment | null>(null);
  const [events, setEvents] = useState<AssessmentEvent[]>([]);
  const [streamState, setStreamState] = useState<RealtimeState>("idle");
  const [loading, setLoading] = useState(true);
  const [unauthenticated, setUnauthenticated] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function loadWorkspace() {
      setLoading(true);
      setError(null);
      try {
        const identity = await api.getMe();
        if (cancelled) return;
        setMe(identity);
        const [readinessResult, assessmentResult] = await Promise.allSettled([
          api.getReadiness(),
          api.listAssessments(),
        ]);
        if (cancelled) return;
        if (readinessResult.status === "fulfilled") {
          setReadiness(readinessResult.value);
        } else {
          setReadiness(readinessFromError(readinessResult.reason));
        }
        if (assessmentResult.status === "fulfilled") {
          setAssessments(assessmentResult.value.results);
          setSelectedId((current) => current || assessmentResult.value.results[0]?.run_id || null);
        } else {
          setError("Assessment history is unavailable from the control plane.");
        }
      } catch (loadError) {
        if (cancelled) return;
        if (loadError instanceof ApiError && [401, 403].includes(loadError.status)) {
          setUnauthenticated(true);
        } else {
          setError("The control plane could not be reached. No local or simulated state was used.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void loadWorkspace();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!selectedId) {
      setSelected(null);
      setEvents([]);
      return;
    }
    let cancelled = false;
    const stream = new AssessmentEventsStream(api, selectedId, {
      onState: setStreamState,
      onError: () => {
        if (!cancelled) setError("Realtime delivery is unavailable; the client will reconnect from its cursor.");
      },
      onSnapshot: (snapshot) => {
        if (cancelled) return;
        setEvents((current) => mergeEvents(current, snapshot.events));
        setSelected((current) =>
          current
            ? {
                ...current,
                state: snapshot.run_state || current.state,
                terminal: snapshot.terminal,
                events: mergeEvents(current.events || [], snapshot.events),
                last_sequence: snapshot.last_sequence,
              }
            : current,
        );
      },
    });

    setEvents([]);
    void api
      .getAssessment(selectedId)
      .then((assessment) => {
        if (cancelled) return;
        setSelected(assessment);
        setEvents(assessment.events || []);
      })
      .catch(() => {
        if (!cancelled) setError("The selected assessment is no longer visible to this identity.");
      });
    void stream.start();
    return () => {
      cancelled = true;
      stream.stop();
    };
  }, [selectedId]);

  const selectedFindings = useMemo(() => selected?.findings || [], [selected]);
  if (loading) {
    return <main className="centered-state"><div className="state-card"><p className="eyebrow">CONTROL PLANE</p><h1>Loading governed workspace</h1><p>Reading session, readiness, and persisted assessment state.</p></div></main>;
  }
  if (unauthenticated || !me) return <LoginRequired />;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">VULNHUNTER / EXECUTION WORKSPACE</p>
          <h1>Assessment operations</h1>
        </div>
        <div className="identity-badge">
          <span className="identity-dot" />
          <span>{me.reviewer_id}</span>
          <span className="muted">{me.roles.join(" · ")}</span>
        </div>
      </header>

      <main className="workspace-grid">
        <aside className="sidebar-panel">
          <section className="readiness-card">
            <div className="panel-heading"><span>Deployment readiness</span><span className={readiness?.ready ? "ready-dot" : "blocked-dot"} /></div>
            <strong>{readiness?.status || (readiness?.ready ? "ready" : "unavailable")}</strong>
            <p>{readiness?.ready ? "The backend reported a ready state." : "Execution remains governed by backend readiness and approvals."}</p>
          </section>
          <section className="assessment-list-panel">
            <div className="panel-heading"><span>Assessments</span><span className="count-pill">{assessments.length}</span></div>
            {assessments.length === 0 ? (
              <p className="empty-copy">No visible persisted assessments for this identity.</p>
            ) : (
              <div className="assessment-list">
                {assessments.map((assessment) => (
                  <button
                    className={`assessment-row ${selectedId === assessment.run_id ? "is-selected" : ""}`}
                    key={assessment.run_id}
                    onClick={() => setSelectedId(assessment.run_id)}
                    type="button"
                  >
                    <span className={statusClass(assessment.state)}>{assessment.state}</span>
                    <strong>{assessment.target || assessment.run_id}</strong>
                    <small>{formatDate(assessment.updated_at)}</small>
                  </button>
                ))}
              </div>
            )}
          </section>
        </aside>

        <section className="detail-panel">
          {error && <div className="notice notice-warning">{error}</div>}
          {!selected ? (
            <div className="empty-detail"><p className="eyebrow">NO ASSESSMENT SELECTED</p><h2>Choose a persisted assessment</h2><p>The client only displays control-plane state returned for the current identity.</p></div>
          ) : (
            <>
              <div className="detail-heading">
                <div>
                  <p className="eyebrow">ASSESSMENT {selected.run_id}</p>
                  <h2>{selected.target || "Assessment detail"}</h2>
                  <p className="muted">Created {formatDate(selected.created_at)} · Updated {formatDate(selected.updated_at)}</p>
                </div>
                <div className="detail-status"><span className={statusClass(selected.state)}>{selected.state}</span><span className={`stream-state stream-${streamState}`}>{streamState.replace("_", " ")}</span></div>
              </div>

              <div className="summary-grid">
                <div><span>Profile</span><strong>{selected.profile || "not reported"}</strong></div>
                <div><span>Scanner</span><strong>{selected.scanner || "not reported"}</strong></div>
                <div><span>Execution</span><strong>{selected.execution_state || "not reported"}</strong></div>
                <div><span>Cursor</span><strong>{selected.last_sequence ?? events.at(-1)?.sequence ?? 0}</strong></div>
              </div>

              {selected.blocking_reason && <div className="notice notice-blocked"><strong>Backend blocked state:</strong> {selected.blocking_reason}</div>}

              <section className="timeline-section">
                <div className="section-heading"><div><p className="eyebrow">DURABLE EVENT TIMELINE</p><h3>Live assessment activity</h3></div><span className="cursor-label">cursor {selected.last_sequence ?? 0}</span></div>
                {events.length === 0 ? <p className="empty-copy">No persisted events have been published for this assessment.</p> : (
                  <div className="timeline">
                    {events.map((event) => (
                      <article className="timeline-entry" key={`${event.sequence}-${event.event_id || event.type || "event"}`}>
                        <div className="timeline-marker" />
                        <div className="timeline-body">
                          <div className="timeline-meta"><span>{event.type || "event"}</span><span>#{event.sequence}</span><time>{formatDate(event.occurred_at)}</time></div>
                          <p>{eventLabel(event)}</p>
                          <div className="chip-row">{event.stage && <span className="chip">stage: {event.stage}</span>}{event.metadata && Object.entries(event.metadata).slice(0, 3).map(([key, value]) => <span className="chip" key={key}>{key}: {String(value)}</span>)}</div>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </section>

              <section className="findings-section"><div className="section-heading"><div><p className="eyebrow">PERSISTED PROJECTIONS</p><h3>Findings</h3></div><span className="count-pill">{selectedFindings.length}</span></div>{selectedFindings.length === 0 ? <p className="empty-copy">No findings were returned for this assessment.</p> : <div className="finding-list">{selectedFindings.map((finding, index) => <div className="finding-row" key={String(finding.id || index)}><span className="finding-severity">{finding.severity || "unclassified"}</span><strong>{finding.title || finding.summary || "Finding"}</strong><span className="muted">{finding.status || "status not reported"}</span></div>)}</div>}</section>
            </>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
