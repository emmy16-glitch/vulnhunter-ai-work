# Governed Publication Operations

This runbook covers the separately activated local final-report publication service. It does not authorize publication, create governance identities, publish a report, merge code, deploy software, or close a finding.

## Activation boundary

Publication is disabled when both of these are unset:

- `VULNHUNTER_PUBLICATION_SIGNING_KEY_FILE`
- `VULNHUNTER_PUBLICATION_CONFIG_FILE`

A partial activation is unsafe and fails preflight. The signing key and configuration must be regular owner-private files. The configuration must declare at least three distinct release authorities and at least one deployment-owned local-directory destination. Four active `campaign_admin` authorities are recommended so requester, approver, publisher, and an independent revoker can all be different people.

Destination roots must already exist, be owned by the application account, use mode `0700` or narrower, and have enough free storage. Destination paths are deployment-owned and never accepted from a browser, chat message, model, or release request.

## Preflight

Run as the unprivileged application account after secrets, governance state, publication state, and destination storage are mounted:

```bash
python manage.py vh_publication_preflight --probe-writes
```

Machine-readable output:

```bash
python manage.py vh_publication_preflight --probe-writes --json
```

Optional thresholds:

```bash
python manage.py vh_publication_preflight \
  --minimum-free-mib 256 \
  --stale-after-minutes 60 \
  --probe-writes
```

The command verifies, without publishing anything:

- complete activation and owner-private key/configuration files;
- governance-store integrity;
- every configured authority exists, is active, and holds `campaign_admin`;
- authority separation capacity, including a warning when only three authorities exist;
- destination identity, ownership, permissions, free space, and optional create/fsync/delete probes;
- every signed request, approval, publication, correction, and revocation record;
- cross-record IDs and SHA-256 bindings;
- at most one current publication for a finding;
- published artifact sizes and digests;
- signed publication manifests, correction notices, and revocation notices;
- stale staging or interrupted metadata operations.

A failed preflight blocks operator activation. It does not alter signed records or publication artifacts.

## Inspect interrupted operations

Inspection is always the default:

```bash
python manage.py vh_publication_recover
```

JSON output:

```bash
python manage.py vh_publication_recover --json
```

The inspection can report:

- a staging directory older than the configured recovery threshold;
- a recent staging directory that may belong to an active publisher;
- a signed publication missing its copied signed manifest;
- a signed correction or revocation missing its destination notice;
- a missing, changed, unsafe, or unreadable artifact;
- a destination policy that no longer matches signed state;
- an artifact directory without a matching signed publication record;
- invalid or cross-linked signed publication state.

Recent staging directories are warnings. Do not recover them until the publishing process is confirmed stopped and the threshold has elapsed.

## Apply narrowly safe recovery

After stopping publication writers and taking a backup, apply only deterministic repairs:

```bash
python manage.py vh_publication_recover \
  --apply-safe \
  --stale-after-minutes 60
```

Safe recovery may only:

1. remove a direct child staging directory whose name starts with `.publication-`, is not a symlink, and is older than the operator threshold;
2. recreate a missing `publication-manifest.json` from the verified signed publication record;
3. recreate a missing `correction.json` from the verified signed correction record;
4. recreate a missing `revocation.json` from the verified signed revocation record.

Safe recovery never:

- publishes a report;
- creates, edits, rolls back, or deletes signed state records;
- changes governance identities or authority membership;
- overwrites an existing metadata file;
- recreates, replaces, or deletes a report artifact;
- deletes an orphan publication directory;
- treats a modified artifact as recoverable;
- selects a new destination;
- closes a finding, merges code, or deploys software.

## Manual escalation

Stop publication writers and preserve the complete destination and state roots before investigating any non-recoverable blocker.

Do not continue automatically when:

- an artifact digest or size differs from the signed manifest;
- a metadata file exists but differs from signed state;
- a publication directory exists without a signed publication record;
- a signed publication references a missing destination configuration;
- more than one current publication exists for a finding;
- signed state or governance integrity fails.

Record the incident, preserve filesystem metadata and logs, restore into an isolated copy, and determine whether the last reviewed backup or a new separately authorized correction/revocation is required. Never repair these cases by editing JSON, copying an unverified artifact, or deleting evidence in place.

## Release sequence

For an activated deployment:

```bash
python manage.py check
python manage.py migrate --plan
python manage.py vh_publication_preflight --probe-writes
python manage.py vh_publication_recover
python manage.py check --deploy
```

Run preflight before enabling publication and after key rotation, governance identity changes, destination changes, restore exercises, or publication incidents.
