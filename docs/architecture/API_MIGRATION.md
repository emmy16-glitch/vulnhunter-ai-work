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

The WebSocket route is `/ws/api/v1/assessments/{assessment_id}/events/`. The client must first obtain a short-lived ticket through the authenticated API, then send that ticket and its last confirmed cursor as the first JSON message. The consumer verifies the ticket signature, expiry, authenticated user, route assessment ID, and owner-scoped visibility before returning a persisted catch-up snapshot. It does not contact workers or accept execution commands. Snapshots include a safe provider-neutral `activity_tree` projected from persisted activity transitions; the tree contains only real operational events and explicit `queued`, `running`, `completed`, `blocked`, or `failed` states.

The conversation activity panel uses the WebSocket path in ASGI deployments and reconnects with the last durable sequence. In the local debug WSGI preview, `VULNHUNTER_REALTIME_WEBSOCKET_ENABLED` defaults to false and the existing persisted SSE stream remains the truthful compatibility path; the client does not generate failing socket attempts in that mode.

Redis is intentionally not the scanner authority. Durable assessment/activity records and the existing signed worker protocol remain authoritative. Event publication/fan-out can be added after the persist-before-publish integration is implemented and tested.

## Current authentication boundary

The first API slice uses Django session authentication so it can be introduced without inventing a token format or changing browser CSRF behavior. Native mobile OAuth/OIDC or short-lived access/refresh tokens remain a subsequent migration phase and must use standardized libraries plus OS-backed secure storage in Flutter.

## React/TypeScript client slice

The additive `frontend/` package now provides a typed React/Vite workspace against the live `/api/v1/` contract. It uses the existing Django session and CSRF cookies, renders readiness, owner-scoped assessment history/detail, persisted findings, and a first-class event timeline, and retains Django templates as the compatibility fallback. The event client performs REST cursor catch-up, obtains an assessment-bound ticket, subscribes to the Channels endpoint, deduplicates by sequence, and reconnects from the last confirmed cursor. It contains no provider, worker, database, SSH, governance, scanner, or emulator secrets.

## Flutter/Dart client foundation

The additive `mobile/` package provides native modules for secure credentials, API access, assessment models, ticket-bound WebSocket reconnect, and resumable APK upload. The workspace screen displays readiness, persisted assessment detail, findings, and events, while the APK panel treats upload as an artifact step only. The current server slice does not yet expose a native token exchange or upload route, so those integration points are explicit configuration boundaries and show truthful unavailable/auth-required states rather than inventing endpoints or execution progress. `flutter analyze` and `flutter test` pass with the stable Flutter SDK used for validation.

## Remaining migration phases

The repository still requires post-commit Channels publication, OpenAPI generation/drift checks, PostgreSQL production acceptance, object-storage abstraction, native mobile token exchange, a production upload/artifact API, Redis outage/reconnect tests, and production deployment hardening. The activity trace itself is implemented as an additive projection over the existing durable activity store; provider failover remains internal to the conversation task and does not create a provider-specific activity stream. These remaining items are explicit follow-up work and are not simulated by the client slices.
