# Nuclei Installation and Verification

VulnHunter pins ProjectDiscovery Nuclei `v3.8.0`. A binary is accepted only after
its version output matches the exact pin. The passive template set is accepted
only when the manifest release is `v10.4.5` and every enabled file digest matches.

## Codespaces installation

`.devcontainer/install-nuclei.sh` downloads the official Linux `amd64` or `arm64`
release archive and the official checksum file, verifies the selected archive,
installs the binary below the ignored `.codespaces/tools/` directory and records
provenance. The binary is never committed to Git.

The post-create setup then runs:

```bash
python scripts/nuclei_readiness.py \
  --executable "$VULNHUNTER_NUCLEI_EXECUTABLE" \
  --manifest "$VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST" \
  --template-root "$VULNHUNTER_NUCLEI_TEMPLATE_ROOT" \
  --execution-enabled \
  --output "$VULNHUNTER_NUCLEI_READINESS_REPORT" \
  --require-ready
```

This command performs no scan and no update. It verifies local deployment inputs
only.

## Manual deployments

For another Linux worker, use the same official release and verification process,
then configure an owner-private policy, signing key, spool and evidence roots as
described in `NUCLEI_WORKER_PILOT.md` or `REMOTE_NUCLEI_WORKER.md`.

Do not place binaries, signing keys, SSH identities, worker policies or generated
readiness reports in the repository.
