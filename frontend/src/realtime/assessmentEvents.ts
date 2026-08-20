import { VulnHunterApi } from "../api/client";
import type { AssessmentEventsPayload, AssessmentSnapshot } from "../api/types";

export type RealtimeState = "idle" | "catching_up" | "connecting" | "live" | "reconnecting" | "closed" | "error";

export interface AssessmentEventsStreamOptions {
  onSnapshot: (snapshot: AssessmentSnapshot) => void;
  onState?: (state: RealtimeState) => void;
  onError?: (error: unknown) => void;
}

export class AssessmentEventsStream {
  private readonly api: VulnHunterApi;
  private readonly assessmentId: string;
  private readonly options: AssessmentEventsStreamOptions;
  private socket: WebSocket | null = null;
  private reconnectTimer: number | undefined;
  private stopped = false;
  private reconnectAttempt = 0;
  private cursor = 0;

  constructor(api: VulnHunterApi, assessmentId: string, options: AssessmentEventsStreamOptions) {
    this.api = api;
    this.assessmentId = assessmentId;
    this.options = options;
  }

  async start(): Promise<void> {
    if (!this.assessmentId) return;
    this.stopped = false;
    this.emitState("catching_up");
    try {
      const snapshot = await this.api.getAssessmentEvents(this.assessmentId, this.cursor);
      this.acceptSnapshot(snapshot);
      if (snapshot.terminal) {
        this.stop();
        return;
      }
      await this.connect();
    } catch (error) {
      this.fail(error);
      this.scheduleReconnect();
    }
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer !== undefined) window.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
    this.socket?.close(1000, "client stopped");
    this.socket = null;
    this.emitState("closed");
  }

  private async connect(): Promise<void> {
    if (this.stopped) return;
    this.emitState(this.reconnectAttempt ? "reconnecting" : "connecting");
    const ticket = await this.api.issueRealtimeTicket(this.assessmentId);
    const endpoint = new URL(
      `/ws/api/v1/assessments/${encodeURIComponent(this.assessmentId)}/events/`,
      window.location.origin,
    );
    endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(endpoint);
    this.socket = socket;

    socket.addEventListener("open", () => {
      this.reconnectAttempt = 0;
      socket.send(JSON.stringify({ ticket: ticket.ticket, after_sequence: this.cursor }));
    });
    socket.addEventListener("message", (event) => {
      try {
        const snapshot = JSON.parse(String(event.data)) as AssessmentSnapshot;
        if (snapshot.type !== "assessment.snapshot") return;
        this.acceptSnapshot(snapshot);
        this.emitState(snapshot.terminal ? "closed" : "live");
        if (snapshot.terminal) this.stop();
      } catch (error) {
        this.fail(error);
      }
    });
    socket.addEventListener("error", (event) => this.fail(event));
    socket.addEventListener("close", () => {
      if (this.socket === socket) this.socket = null;
      if (!this.stopped) this.scheduleReconnect();
    });
  }

  private acceptSnapshot(snapshot: AssessmentEventsPayload): void {
    const nextCursor = Number.isFinite(snapshot.last_sequence)
      ? Math.max(this.cursor, snapshot.last_sequence)
      : this.cursor;
    this.cursor = nextCursor;
    this.options.onSnapshot({
      ...snapshot,
      events: Array.isArray(snapshot.events) ? snapshot.events : [],
      last_sequence: nextCursor,
    });
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer !== undefined) return;
    const delay = Math.min(30_000, 500 * 2 ** Math.min(this.reconnectAttempt, 6));
    this.reconnectAttempt += 1;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = undefined;
      void this.connect().catch((error) => {
        this.fail(error);
        this.scheduleReconnect();
      });
    }, delay);
    this.emitState("reconnecting");
  }

  private fail(error: unknown): void {
    this.options.onError?.(error);
    this.emitState("error");
  }

  private emitState(state: RealtimeState): void {
    this.options.onState?.(state);
  }
}
