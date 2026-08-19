import type {
  Assessment,
  AssessmentEventsPayload,
  AssessmentListPayload,
  MePayload,
  ReadinessPayload,
  RealtimeTicketPayload,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly payload: unknown;

  constructor(status: number, payload: unknown) {
    super(`VulnHunter API request failed with HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

function readCookie(name: string): string | null {
  const prefix = `${encodeURIComponent(name)}=`;
  const cookie = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix));
  return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : null;
}

async function parsePayload(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

export class VulnHunterApi {
  private readonly basePath: string;

  constructor(basePath = "/api/v1") {
    this.basePath = basePath.replace(/\/$/, "");
  }

  private url(path: string): string {
    return `${this.basePath}/${path.replace(/^\//, "")}`;
  }

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (init.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    if ((init.method || "GET").toUpperCase() !== "GET") {
      const csrf = readCookie("csrftoken");
      if (csrf) headers.set("X-CSRFToken", csrf);
    }

    const response = await fetch(this.url(path), {
      ...init,
      headers,
      credentials: "include",
    });
    const payload = await parsePayload(response);
    if (!response.ok) throw new ApiError(response.status, payload);
    return payload as T;
  }

  getMe(): Promise<MePayload> {
    return this.request<MePayload>("me/");
  }

  getReadiness(): Promise<ReadinessPayload> {
    return this.request<ReadinessPayload>("readiness/");
  }

  listAssessments(): Promise<AssessmentListPayload> {
    return this.request<AssessmentListPayload>("assessments/");
  }

  getAssessment(assessmentId: string): Promise<Assessment> {
    return this.request<Assessment>(`assessments/${encodeURIComponent(assessmentId)}/`);
  }

  getAssessmentEvents(
    assessmentId: string,
    afterSequence: number,
  ): Promise<AssessmentEventsPayload> {
    const cursor = Math.max(0, Math.trunc(afterSequence));
    return this.request<AssessmentEventsPayload>(
      `assessments/${encodeURIComponent(assessmentId)}/events/?after_sequence=${cursor}`,
    );
  }

  issueRealtimeTicket(assessmentId: string): Promise<RealtimeTicketPayload> {
    return this.request<RealtimeTicketPayload>("realtime/ticket/", {
      method: "POST",
      body: JSON.stringify({ assessment_id: assessmentId }),
    });
  }
}
