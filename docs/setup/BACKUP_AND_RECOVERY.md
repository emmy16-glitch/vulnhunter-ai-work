# Verified backup and recovery

VulnHunter recovery bundles are local, private directories containing consistent database snapshots, governed runtime files, and a checksummed manifest. Bundle creation is fail-closed: the bundle is verified before it is moved into its final destination.

## Included state

For a SQLite deployment, a bundle contains consistent snapshots of:

- the Django web database;
- authorization records;
- governance records;
- agent state;
- approval records;
- adversary-lab state.

The bundle also includes regular files found under configured roots for:

- agent activity;
- security evidence;
- verification records;
- task graphs;
- adversary-lab workspaces and evidence;
- mobile artifacts;
- Nuclei execution records;
- Django media.

Missing optional directories are represented by having no entries. Symlinks and non-regular files are rejected.

## Excluded state

The backup service does not copy secret-key files, provider API keys, worker signing keys, environment variables, source code, installed tools, static assets, or configuration repositories. Manage those through the deployment secret manager and source-control process.

## Create a SQLite bundle

Choose a new destination outside every configured evidence or runtime source directory:

```bash
python manage.py vh_backup_create /srv/vulnhunter-backups/2026-08-01T1900Z
```

The destination must not already exist. VulnHunter creates a private staging directory, snapshots each SQLite database with the SQLite backup API, copies governed files without following symlinks, writes `manifest.json`, restricts directories to owner-only access and files to owner read/write, verifies the complete bundle, and then atomically renames it into place.

Successful output contains counts and stable status fields only. It does not print source paths, file contents, database credentials, or secret values.

## PostgreSQL deployments

VulnHunter does not invoke `pg_dump` with database credentials. Create the dump using the deployment platform's protected database process, then pass the resulting regular file:

```bash
pg_dump --format=custom --file=/secure-staging/vulnhunter.pg_dump "$DATABASE_URL"
python manage.py vh_backup_create \
  /srv/vulnhunter-backups/2026-08-01T1900Z \
  --postgres-dump /secure-staging/vulnhunter.pg_dump
```

A PostgreSQL deployment without a supplied dump is rejected. A dump supplied to a SQLite deployment is also rejected. Bundle verification requires exactly one `web_database` PostgreSQL dump when the manifest declares PostgreSQL mode.

## Verify a bundle

Verification is safe and read-only:

```bash
python manage.py vh_backup_verify /srv/vulnhunter-backups/2026-08-01T1900Z
```

It checks:

- readable supported manifest and application identity;
- safe relative paths with no traversal or symlink escape;
- exact file inventory with no unlisted files;
- recorded sizes and SHA-256 digests;
- SQLite `PRAGMA integrity_check` results;
- database-mode consistency;
- owner-only filesystem permissions.

Any failed check causes a nonzero exit. Never restore an invalid bundle.

## Plan a restore

Restore planning verifies the bundle again and prints the logical actions without changing live state:

```bash
python manage.py vh_backup_restore_plan /srv/vulnhunter-backups/2026-08-01T1900Z
```

SQLite databases and governed file groups are reported as `replace_after_stop`. PostgreSQL is reported as `external_database_restore`. A failed verification produces no actions and a nonzero exit.

## Execute a verified SQLite database restore

Restore execution is intentionally limited to configured SQLite databases. Governed file trees and PostgreSQL remain operator-controlled restore steps.

First stop every VulnHunter web and worker process. Calculate the SHA-256 digest of the exact bundle `manifest.json`, then create an owner-only maintenance marker:

```json
{
  "application": "vulnhunter",
  "maintenance": true,
  "database_mode": "sqlite",
  "bundle_digest": "<sha256-of-manifest.json>"
}
```

The marker must be a regular file with no group or other permissions. Execute the restore with a new rollback directory:

```bash
python manage.py vh_backup_restore_execute \
  /srv/vulnhunter-backups/2026-08-01T1900Z \
  --bundle-digest <sha256-of-manifest.json> \
  --maintenance-marker /srv/vulnhunter-maintenance/restore.json \
  --rollback-directory /srv/vulnhunter-rollback/2026-08-02T0900Z
```

Before changing live state, VulnHunter:

- re-verifies the complete backup bundle;
- requires SQLite deployment mode;
- binds the command and maintenance marker to the exact manifest digest;
- requires the bundle database inventory to match the configured deployment;
- creates integrity-checked owner-only snapshots of every live SQLite database.

Each replacement is staged in the live database directory, checked with SQLite `PRAGMA integrity_check`, and atomically moved into place. After replacement, every database is checked again for integrity and exact backup digest. A failure triggers automatic rollback of every database already replaced. The rollback directory is retained after success or recovered failure for operator inspection and must be archived or removed according to the recovery runbook.

The command does not restore governed file trees, invoke PostgreSQL tooling, start application processes, remove the maintenance marker, or print runtime paths and credentials.

## Operational rules

- Store bundles and rollback snapshots on encrypted storage restricted to recovery operators.
- Copy completed bundles off the application host according to retention policy.
- Verify every copied bundle at its destination.
- Test restore planning and SQLite restore execution in an isolated environment.
- Keep PostgreSQL dump and restore tooling and credentials outside the application process.
- Stop all web and worker processes before restore execution.
- Preserve the original bundle unchanged during recovery.
- Restart services only after independent application readiness and evidence checks pass.
