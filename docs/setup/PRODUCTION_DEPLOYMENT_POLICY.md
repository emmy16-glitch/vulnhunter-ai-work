# Production deployment policy

VulnHunter provides two deployment preflight modes. Both modes evaluate local dependency readiness first and then apply a fail-closed security policy. The command prints only stable check names and `ok` or `failed`; it never prints secret values, host lists, trusted origins, database credentials, or runtime paths.

## Baseline deployment

Use the baseline mode for a private or local production installation:

```bash
python manage.py vh_deployment_preflight
```

The baseline policy requires:

- Django debug mode is disabled.
- The Django secret key is at least 32 characters, has reasonable character diversity, and is not a known placeholder.
- `ALLOWED_HOSTS` is non-empty and does not contain `*`.
- Session and CSRF cookies are HTTP-only.
- Clickjacking protection is `DENY`.
- Runtime configuration, the web database, and the agent store pass readiness checks.

HTTPS is strongly recommended for every production installation, but the baseline mode permits a private loopback or controlled internal deployment where TLS is terminated elsewhere or the service is not publicly reachable.

## Public internet deployment

Use public mode before exposing VulnHunter beyond a private network:

```bash
python manage.py vh_deployment_preflight --public
```

Public mode includes every baseline check and additionally requires:

- VulnHunter HTTPS mode is enabled.
- Session and CSRF cookies are secure.
- HTTP-to-HTTPS redirection is enabled.
- HSTS has a positive duration.
- At least one explicit non-loopback, non-private public host is configured.
- Every trusted CSRF origin uses HTTPS, has a public hostname, and contains no credentials, query string, or fragment.
- PostgreSQL is the configured web database.

Loopback hosts, RFC1918/private IP addresses, `.local`, `.localhost`, and `.internal` names do not satisfy the public-host check.

## Expected output

A successful baseline result has this shape:

```json
{
  "checks": {
    "agent_store": "ok",
    "configuration": "ok",
    "database": "ok"
  },
  "policy": {
    "checks": {
      "allowed_hosts_explicit": "ok",
      "clickjacking_protection": "ok",
      "csrf_cookie_httponly": "ok",
      "debug_disabled": "ok",
      "secret_key_strong": "ok",
      "session_cookie_httponly": "ok"
    },
    "mode": "baseline",
    "status": "ready"
  },
  "status": "ready"
}
```

The command exits nonzero when either dependency readiness or policy validation fails. Deployment automation should treat any nonzero exit as a hard stop.

## Health and readiness endpoints

- `/health/` remains a lightweight liveness endpoint.
- `/ready/` remains the stable dependency-readiness endpoint for load balancers.
- Deployment policy is intentionally enforced by `vh_deployment_preflight`, because public exposure requirements are deployment decisions rather than per-request liveness checks.
