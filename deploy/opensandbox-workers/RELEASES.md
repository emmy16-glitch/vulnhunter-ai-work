# OpenSandbox worker release trust

VulnHunter must not activate an OpenSandbox scanner worker from an image digest alone.
Every enabled Bandit or Nuclei image must also have one exact `approved` entry in a detached
Ed25519-signed worker release registry.

Production release is intentionally split into two authorities:

1. GitHub Actions may build and publish a **candidate** worker plus verifiable supply-chain evidence.
2. A separate offline release authority reviews that candidate and may promote it to `approved` or
   `revoked`, then signs the complete runtime registry with the offline production Ed25519 key.

A GitHub workflow can never make a worker runtime-authoritative by itself.

## Trust boundary

Production VulnHunter receives only:

- `releases.json` — canonical candidate/approved/revoked worker release records
- `releases.sig.json` — detached Ed25519 signature over the canonical registry JSON
- `releases.pub.pem` — the trusted Ed25519 public verification key

The private signing key is an offline/owner-controlled release secret. It must never be placed in
an application image, repository, GitHub Actions secret, worker image, OpenSandbox container,
runtime environment file, or deployment volume accessible to VulnHunter.

## Release record schema

Schema version 2 records bind:

- stable worker ID (`bandit` or `nuclei`)
- stable release ID
- immutable OCI repository image reference ending in `@sha256:<digest>`
- SPDX SBOM SHA-256
- VulnHunter SLSA/in-toto-style provenance SHA-256
- source Git commit
- state: `candidate`, `approved`, or `revoked`
- optional `rollback_of` release ID
- GitHub SLSA provenance attestation-bundle SHA-256, when present
- GitHub SPDX SBOM attestation-bundle SHA-256, when present
- exact GitHub Actions signer-workflow identity, when attestations are present

GitHub attestation fields are all-or-none. A remote production OpenSandbox control plane requires
them on every selected approved release. Loopback acceptance environments may use approved signed
records without GitHub attestation fields so deterministic local worker acceptance does not depend
on an external attestation service.

Schema version 1 registries remain readable for compatibility with already-generated local
acceptance evidence, but they cannot satisfy the remote-production attestation requirement.

Release IDs are globally unique. Historical records may refer to the same worker image, but only
one record for a given worker/image pair may be `approved` at a time. A `rollback_of` value must
reference an existing release for the same worker; this keeps rollback history explicit without
making an image selection ambiguous.

`candidate` is never selectable by `approved_release()`. Merely signing a registry that contains a
candidate does not make that image executable.

VulnHunter copies the selected release ID, SBOM digest, provenance digest, source commit, signed
registry digest, signing-key ID, GitHub provenance-attestation digest, GitHub SBOM-attestation
digest, and signer-workflow identity into the immutable `CommandPlan`. Execution fails if any of
those fields change after plan issuance.

## Immutable worker inputs

Both production worker Containerfiles use the same reviewed Python base image pinned by repository
SHA-256 rather than a mutable tag:

```text
python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134
```

The release provenance generator refuses a worker Containerfile whose `PYTHON_BASE_IMAGE` is not
pinned by SHA-256 and records that base digest as a resolved dependency.

Nuclei remains additionally pinned to its reviewed release archive and archive checksum. Bandit
remains pinned to the reviewed top-level Bandit version.

A pinned base does not imply bit-for-bit reproducible builds. Debian package repositories and
Bandit's transitive Python dependency resolution can still change over time. The authoritative
identity is therefore the built OCI digest plus its reviewed evidence and attestations, not an
assumption that rebuilding later will reproduce the same digest.

## Pull-request acceptance evidence

`.github/workflows/opensandbox-worker.yml` remains the real integration acceptance path. It builds
each worker, publishes it to an ephemeral local registry, obtains the immutable repository digest,
generates an SPDX package inventory and provenance, creates an ephemeral Ed25519 signing key,
signs the release registry, verifies the signature, and only then runs the real
VulnHunter -> OpenSandbox acceptance path.

The CI private key is deleted immediately after signing. Public release evidence is uploaded as a
short-lived workflow artifact. CI keys are acceptance-only and are never production trust roots.

## Production candidate publisher

`.github/workflows/opensandbox-worker-release.yml` is a separate manual-only publisher. It is not a
pull-request publishing workflow.

The publisher:

1. requires `workflow_dispatch` and the exact confirmation `PUBLISH_OPEN_SANDBOX_WORKER`;
2. fails unless the workflow is running from `refs/heads/main`;
3. builds exactly the checked-out `GITHUB_SHA` and does not accept an arbitrary source commit;
4. accepts only the explicit `bandit` or `nuclei` worker choice;
5. rejects malformed or reused candidate release IDs;
6. logs into GHCR with the scoped workflow token and pushes the worker under candidate/source tags;
7. captures the immutable GHCR `@sha256` repository identity;
8. generates the VulnHunter SPDX SBOM and source/base-image provenance for that exact image;
9. creates keyless GitHub SLSA provenance and SPDX SBOM attestations for that exact OCI digest;
10. copies the exact Sigstore attestation bundles returned by GitHub;
11. immediately verifies each exact bundle with `gh attestation verify`, binding repository,
    signer workflow, `refs/heads/main`, source commit, predicate type, and GitHub-hosted runner;
12. creates a `candidate` record whose hashes bind those exact verified bundles;
13. uploads the candidate evidence for offline review;
14. explicitly stops without creating an `approved` record or any Ed25519 signature.

Third-party actions in this production workflow are pinned to exact reviewed commit SHAs rather
than floating major-version tags.

The workflow intentionally does **not** contain the production Ed25519 private key.

## Offline approval procedure

After a successful candidate workflow, the release owner performs approval outside GitHub Actions:

1. Download the candidate evidence artifact through the controlled release channel.
2. Verify `checksums.txt` before reviewing individual evidence files.
3. Confirm `image.txt` is the intended GHCR repository digest and the candidate source commit is the
   reviewed `main` commit.
4. Re-run GitHub attestation verification for the preserved provenance bundle, enforcing the exact
   repository, signer workflow, `refs/heads/main`, source digest, and GitHub-hosted runner.
5. Re-run GitHub attestation verification for the preserved SBOM bundle with predicate type
   `https://spdx.dev/Document/v2.3` and the same identity constraints.
6. Review the SPDX SBOM, VulnHunter provenance, pinned base digest, scanner version, Containerfile,
   and candidate release record.
7. Promote the immutable candidate record without editing its evidence identity:

   ```bash
   python scripts/opensandbox_worker_release.py promote \
     --candidate candidate.json \
     --status approved \
     --output approved.json
   ```

   Use `--status revoked` when review rejects the candidate. For a rollback approval, also pass the
   reviewed predecessor release ID with `--rollback-of`.
8. Combine the new promoted record with the complete historical release records:

   ```bash
   python scripts/opensandbox_worker_release.py registry \
     --record historical-1.json \
     --record historical-2.json \
     --record approved.json \
     --output releases.json
   ```

9. Sign the complete registry with the offline production Ed25519 private key and matching public
   key:

   ```bash
   python scripts/opensandbox_worker_release.py sign \
     --registry releases.json \
     --private-key /offline/trust-root/releases.key.pem \
     --public-key releases.pub.pem \
     --signature releases.sig.json
   ```

10. Verify the exact selected image against the signed registry before publication:

    ```bash
    python scripts/opensandbox_worker_release.py verify \
      --registry releases.json \
      --signature releases.sig.json \
      --public-key releases.pub.pem \
      --worker-id bandit \
      --image ghcr.io/owner/vulnhunter-opensandbox-bandit@sha256:<digest>
    ```

11. Publish only `releases.json`, `releases.sig.json`, `releases.pub.pem`, the reviewed SBOM,
    provenance, and attestation evidence through the controlled deployment channel.
12. Configure `VULNHUNTER_OPENSANDBOX_*_IMAGE` to the exact approved GHCR digest and mount the three
    signed-registry trust files read-only.
13. For a remote control plane, use HTTPS. Runtime activation additionally refuses approved releases
    that do not contain the GitHub provenance/SBOM attestation identity.
14. Require activation and worker acceptance to succeed before enabling user traffic.

## Revocation and rollback

Revocation never deletes history. Change the old release to `revoked`, add the replacement or
rollback record, then re-sign the entire registry offline.

A rollback creates a **new** approved release record for the selected historical image and sets
`rollback_of` to the release being backed out. Any older record selecting that same image must
remain non-approved so the runtime has exactly one active approval for the worker/image pair.

## Fail-closed cases

Activation is denied when:

- the registry/signature/public-key files are missing
- any trust file is a symlink or not a regular file
- the registry/signature exceeds its bounded size
- JSON contains duplicate keys or unexpected fields
- the public key is not Ed25519
- the detached signature is invalid
- the signature key ID does not match the mounted public key
- the configured image is not present in the signed registry
- the matching image is only `candidate` or `revoked`
- the matching image has no approved release
- more than one approved release selects the same worker/image pair
- release IDs are duplicated
- `rollback_of` references a missing release or a different worker
- an image is mutable instead of digest-pinned
- a schema-v2 GitHub attestation identity is partial or malformed
- a remote OpenSandbox control plane selects an approved release without both GitHub attestation
  bundle hashes and the signer-workflow identity
- the command plan's release or attestation identity changes after authorization

## Remaining operational prerequisites

This implementation provides the application and release-pipeline enforcement, but it does not
pretend the production environment already exists. Before the first live worker release, operators
still need to establish and document:

- the real offline Ed25519 trust-root creation/storage/recovery ceremony
- GHCR package visibility and least-privilege ACLs
- registry retention and deletion protection for approved/revoked image digests
- long-lived storage for reviewed SBOM, provenance, attestation bundles, and signed registries
- deployment secret handling for the OpenSandbox API key
- production HTTPS/TLS policy for the remote OpenSandbox control plane
- a human release-review record identifying who promoted and signed each release

No production worker is considered deployed merely because the candidate workflow succeeds.
