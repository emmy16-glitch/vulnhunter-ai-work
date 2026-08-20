# VulnHunter React/TypeScript client

This directory contains the first additive React/TypeScript client slice for the versioned VulnHunter control-plane API. Django remains authoritative for identity, role authorization, scope, approvals, worker activation, findings, evidence, and lifecycle state. The client only requests and renders server-provided projections.

The client uses the existing browser session cookie and Django CSRF cookie through `credentials: "include"`. It does not invent bearer tokens, put credentials in URLs, or contain provider, worker, database, SSH, governance, scanner, or emulator secrets. The realtime flow first reads persisted events from `GET /api/v1/assessments/{id}/events/?after_sequence=N`, then obtains a short-lived assessment-bound ticket from `POST /api/v1/realtime/ticket/` and subscribes to `ws/api/v1/assessments/{id}/events/`. Reconnects resend the last confirmed sequence so durable state is the source of truth.

Run `pnpm install`, `pnpm run typecheck`, and `pnpm run build` from this directory. `pnpm dev` proxies `/api` and `/ws` to the local Django control plane at `127.0.0.1:8000`. The legacy Django workspace remains available as the compatibility and fallback surface while client parity is expanded.
