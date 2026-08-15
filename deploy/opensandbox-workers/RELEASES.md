# OpenSandbox worker release trust

VulnHunter must not activate an OpenSandbox scanner worker from an image digest alone.
Every enabled Bandit or Nuclei image must also have one exact `approved` entry in a detached
Ed25519-signed worker release registry.

## Trust boundary

Production VulnHunter receives only:

- `releases.json` — canonical approved/revoked worker release records
- `releases.sig.json` — detached Ed25519 signature over the canonical registry JSON
- `releases.pub.pem` — the trusted Ed25519 public verification key

The private signing key is an offline/owner-controlled release secret. It must never be placed in
an application image, repository, worker image, OpenSandbox container, runtime environment file,
or deployment volume accessible to VulnHunter.

## Release record

Each signed record binds:

- stable worker ID (`bandit` or `nuclei`)
- stable release ID
- immutable OCI repository image reference ending in `@sha256:<digest>`
- SPDX SBOM SHA-256
- SLSA/in-toto-style provenance SHA-256
- source Git commit
- state: `approved` or `revoked`
- optional `rollback_of` release ID

VulnHunter copies the selected release ID, SBOM digest, provenance digest, source commit, signed
registry digest, and signing-key ID into the immutable `CommandPlan`. Execution fails if any of
those fields change after plan issuance.

## CI evidence

`.github/workflows/opensandbox-worker.yml` builds each worker, publishes it to an ephemeral local
registry, obtains the immutable repository digest, generates an SPDX package inventory from the
actual built image, generates provenance for the exact Containerfile and checked-out commit,
creates an ephemeral Ed25519 signing key, signs the release registry, verifies the signature, and
only then runs the real VulnHunter -> OpenSandbox acceptance path.

The CI private key is deleted immediately after signing. Public release evidence is uploaded as a
short-lived workflow artifact. CI keys are acceptance-only and are never production trust roots.

## Production release procedure

1. Build the reviewed worker from a reviewed commit and Containerfile.
2. Push to the approved private registry and capture the immutable repository `@sha256` digest.
3. Generate the SBOM and provenance from that exact image and source commit.
4. Create a new release record with a unique release ID.
5. If replacing a compromised or invalid release, leave the old record in the registry with
   `status: revoked`.
6. If intentionally rolling back, create a new approved record for the selected older image and set
   `rollback_of` to the release being backed out.
7. Sign the complete registry with the offline production Ed25519 private key.
8. Publish the registry, detached signature, public key, SBOM, and provenance through the controlled
   deployment/release channel.
9. Configure `VULNHUNTER_OPENSANDBOX_*_IMAGE` to the exact approved digest and mount the three trust
   files read-only.
10. Restart/reload the application and require activation plus worker acceptance to succeed before
    enabling user traffic.

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
- the matching release is revoked
- release IDs or worker/image identities are duplicated
- an image is mutable instead of digest-pinned

This layer does not replace registry ACLs, image retention, vulnerability scanning, or future OCI
transparency/cosign attestations. It provides the application-side cryptographic allowlist that
must succeed before VulnHunter will create an OpenSandbox execution backend.
