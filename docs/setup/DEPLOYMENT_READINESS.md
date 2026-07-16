# Deployment Readiness and Operations Boundary

VulnHunter is code-ready for a reviewed hosting design, but this repository does
not deploy itself. Hosting, DNS, TLS, production secrets, persistent storage,
backup scheduling, monitoring, and any external capability activation are
operator-controlled prerequisites.

## Required hosting inputs

1. Choose an authorized private hosting boundary and named operators.
2. Generate `VULNHUNTER_WEB_SECRET_KEY` in the deployment secret manager.
3. Set exact `VULNHUNTER_WEB_ALLOWED_HOSTS` and HTTPS origins from
   `.env.example`; do not use wildcard public tunnels as defaults.
4. Terminate TLS at the application server or a trusted reverse proxy. Set
   `VULNHUNTER_WEB_TRUST_PROXY=true` only when the proxy strips inbound
   `X-Forwarded-*` headers before setting its own values. Keep HSTS subdomains
   and browser preload disabled until every subdomain is HTTPS-only and the
   operator accepts the long-lived, difficult-to-reverse browser policy.
5. Provision persistent state, evidence, activity, mobile-artifact, static, and
   log locations with least-privilege filesystem ownership.
6. Select and test the production database/storage design. Set
   `VULNHUNTER_WEB_DATABASE_ENGINE=postgresql` and the documented PostgreSQL
   variables for production. The optional `production` dependency group supplies
   Gunicorn and psycopg; database provisioning, credentials, TLS policy, migration
   rehearsal, and restore proof remain operator responsibilities.
7. Use `vulnhunter.web.wsgi:application` with the conservative
   `config/deployment/gunicorn.conf.py`. Django's development server is local only.
8. Initialize the versioned agent store explicitly before starting application
   workers. Do not create an empty SQLite file manually.

## Safe startup order

Run these as the unprivileged application account after storage and secrets are
mounted, but before enabling a service:

```bash
python manage.py check
python manage.py migrate --plan
python manage.py migrate
python manage.py vh_init_agent_store
python manage.py collectstatic --noinput
python manage.py check --deploy
gunicorn --config config/deployment/gunicorn.conf.py vulnhunter.web.wsgi:application
```

`vh_init_agent_store` validates an existing schema and refuses malformed data. A
legacy store requires the explicit `--migrate-legacy` flag and is backed up before
its metadata-only migration. The service template is documentation only at
`docs/setup/systemd/vulnhunter.service.example`; copying/enabling it is a later
privileged operator action.

## Preflight gates

Run from the exact release worktree with deployment environment variables loaded:

```bash
python -m ruff check .
python -m ruff format --check .
python -m compileall -q vulnhunter
python -m pytest -q -x --tb=short
python -m django check
python -m django check --deploy
python -m django makemigrations --check --dry-run
python manage.py migrate --plan
python manage.py collectstatic --noinput --dry-run
python scripts/security_tool_status.py --require-standard
```

`GET /health/` is a process liveness check. `GET /ready/` checks the Django
database, versioned agent store, and security-tool runtime configuration without
starting a tool, connector, model, scan, or external request. A failed required
dependency returns HTTP 503.

## Storage ownership and logging

- `/srv/vulnhunter/state`: mode `0750` or narrower; databases and graph state.
- `/srv/vulnhunter/evidence`: mode `0750` or narrower; evidence, activity, media,
  and mobile artifacts.
- `/srv/vulnhunter/static`: collected static files, writable only during release.
- `/srv/vulnhunter/log`: application logs when stdout/stderr is not journal-owned.

The application account must own writable paths. Gunicorn logs to stdout/stderr by
default; use journald retention or an operator-reviewed `logrotate` policy. Never
put raw prompts, credentials, authorization values, cookies, or evidence bodies in
logs.

## Backup and rollback

Before a release, stop application writers and take consistent backups of every
configured SQLite database, task graph, activity ledger, evidence root, mobile
artifact root, and deployment configuration. Verify restoration into an isolated
directory and run integrity/readiness checks there.

Application rollback means selecting the previously reviewed source release and
its matching dependency set, then restoring data only when its schema contract
requires it. Do not use Git reset/checkout as a production data rollback. The
security-tool integration installer has its own exact backup recorded in
`var/install/vulnhunter-security-tool-integration-20260715.json`.

For PostgreSQL, take an authenticated custom-format backup and prove restore in an
isolated database before release. Example operator commands (do not run from an
untrusted shell and do not place the password on the command line):

```bash
pg_dump --format=custom --file=/secure-backup/vulnhunter.dump "$PGDATABASE"
createdb vulnhunter_restore_check
pg_restore --clean --if-exists --no-owner --dbname=vulnhunter_restore_check \
  /secure-backup/vulnhunter.dump
```

Rollback order is: stop writers, preserve current logs/evidence, restore the last
reviewed application/dependency release, run schema compatibility checks, restore
data only when the reviewed rollback plan requires it, then re-run `/ready/` and
governance integrity tests. Never reset source as a substitute for data rollback.

## Separate activation gates

Hosting does not authorize targets or enable tools. Security-tool execution,
Machine Oracle, providers, Graphify, MCP, dynamic Android analysis, emulators,
privileged brokerage, and finding publication retain their independent scope,
approval, credential, isolation, evidence, audit, and human-review gates.
