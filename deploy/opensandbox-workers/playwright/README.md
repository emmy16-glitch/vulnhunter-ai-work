# VulnHunter passive Playwright worker

This image is a **browser-perception collector**, not an exploitation worker.

Security properties:

- Playwright is pinned to `1.62.0`.
- The Python base image is pinned by immutable OCI SHA-256 digest.
- OpenSandbox launches the worker process as UID/GID `65532`.
- OpenSandbox egress is default-deny with only the plan's pinned IPv4 destination allowed.
- Chromium receives an explicit hostname-to-approved-IP resolver rule.
- Chromium's *nested* Linux namespace sandbox is deliberately disabled. The worker is allowed to
  run only inside the outer OpenSandbox/Docker boundary, where it remains non-root, capabilities
  are dropped, `no_new_privileges` remains enabled, and egress remains exact-target/default-deny.
  The nested namespace sandbox cannot initialize under that outer profile; do not run this worker
  directly on a host or in a broadly privileged container.
- Service workers are blocked.
- WebSockets are blocked before connection.
- Only GET/HEAD requests to the exact authorized scheme/hostname/port/path boundary continue.
- Forms are **described but never submitted**.
- No clicks, uploads, credentials, payload injection, screenshots, traces, HAR files, cookies,
  local/session storage, request/response headers, response bodies, or page text are exported.
- Query strings and fragments are removed from exported URLs.
- DOM evidence is a SHA-256 of tag names and attribute names only.
- All target-derived strings remain tagged as `untrusted_target_content`.

The worker is intentionally limited to the private/laboratory target policy enforced by the
VulnHunter branch it ships with. Production publication is not enabled by this batch; the
worker must first pass the same signed-release promotion process used by other OpenSandbox
workers.
