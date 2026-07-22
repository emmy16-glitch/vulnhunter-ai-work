# Governed Security Tool Integration

The security-tool registry reports four separate facts: local installation,
adapter support, required safety gate and current operational readiness.
Detection never grants execution authority.

## Registered catalog

The catalog includes network, source, secret, dependency, SBOM, binary and
Android tools. Most entries are registrations or connector contracts. They are
not automatically installed by the Python package and do not become runnable web
workflows merely because a binary is found on `PATH`.

The controlled Nuclei passive worker is the currently operational network-scanner
workflow when every private-lab gate is verified. Other tools remain installed-only,
registry-only or connector-required until their own reviewed workflow exists.

## Nuclei activation boundary

`config/security_tools/runtime.json` permits the reviewed private-lab path, but a
job still fails closed unless all of these are present:

- pinned Nuclei `v3.8.0`;
- reviewed template release `v10.4.5` with matching SHA-256 files;
- owner-private worker policy and signing key;
- signed manager-to-worker spool;
- exact active RFC1918 authorization;
- passive profile and fixed resource limits;
- independent approval of the immutable plan digest.

Public targets and unrestricted execution remain disabled.

## Readiness probes

The registry performs bounded shell-free version probes. Missing, timed-out,
misidentified or non-zero probes are never reported as ready. ProjectDiscovery
`httpx` is checked with its own identity output and the detector tries
`httpx-toolkit` before `httpx`, avoiding the Python HTTPX command-name collision.

Bulk probes use at most two workers to match the supported small VM.

## Codespaces

The phone-only Codespaces environment installs and checksum-verifies the pinned
Nuclei release, copies the reviewed passive templates into an ignored runtime
directory, creates an owner-private signing key and worker policy, and writes a
strict readiness report. Use `docs/setup/PHONE_ONLY_PRIVATE_LAB.md` for the full
operator flow.
