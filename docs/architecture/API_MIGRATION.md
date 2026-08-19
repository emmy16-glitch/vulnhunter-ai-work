# VulnHunter API and ASGI Migration

This document records the first additive migration slice from the Architecture Migration Specification. Django remains the authoritative control plane. Existing server-rendered workspace routes, authorization services, signed worker spools, artifact validation, and SSE endpoints remain active and are not replaced by frontend or Redis logic.

## Versioned API surface

The current slice mounts the following authenticated session-based resources under `/api/v1/`:

| Resource | Method | Purpose |
|---|---:|---|
| `/api/v1/me/` | GET | Return the authenticated Django identity, mapped reviewer identity, and product roles. |
| `/api/v1/readiness/` | GET | Return the existing deployment readiness projection. |
| `/api/v1/assessments/` | GET | Return the existing owner-scoped recent assessment projection. |
| `/api/v1/assessments/{id}/` | GET | Return the existing authorized assessment projection. |
| `/api/v1/assessments/{id}/events/` | GET | Return persisted events after an explicit cursor. |
| `/api/v1/realtime/ticket/` | POST | Issue a short-lived assessment-bound realtime ticket after server-side visibility checks. |

These endpoints are adapters over existing services. They do not duplicate authorization, create scanner jobs, change target scope, or expose raw worker output by default.

## ASGI and realtime

`vulnhunter/web/asgi.py` is now the ASGI entrypoint for HTTP and WebSocket traffic. WSGI remains configured for compatibility during rollout. Channels uses an in-memory layer only in tests/debug development. Non-debug deployments must set `VULNHUNTER_REDIS_URL`; otherwise settings fail closed rather than silently claiming production realtime readiness.

The WebSocket route is `/ws/api/v1/assessments/{assessment_id}/events/`. The client must first obtain a short-lived ticket through the authenticated API, then send that ticket as the first JSON message. The consumer verifies the ticket signature, expiry, authenticated user, route assessment ID, and owner-scoped visibility before returning a persisted catch-up snapshot. It does not contact workers or accept execution commands.

Redis is intentionally not the scanner authority. Durable assessment/activity records and the existing signed worker protocol remain authoritative. Event publication/fan-out can be added after the persist-before-publish integration is implemented and tested.

## Current authentication boundary

The first API slice uses Django session authentication so it can be introduced without inventing a token format or changing browser CSRF behavior. Native mobile OAuth/OIDC or short-lived access/refresh tokens remain a subsequent migration phase and must use standardized libraries plus OS-backed secure storage in Flutter.

## Remaining migration phases

The repository still requires the later specification phases: post-commit Channels publication, OpenAPI generation/drift checks, PostgreSQL production acceptance, object-storage abstraction, React/TypeScript parity screens, Flutter/Dart client, native mobile token flow, Redis outage/reconnect tests, and production deployment hardening. These are intentionally not simulated by this slice.
