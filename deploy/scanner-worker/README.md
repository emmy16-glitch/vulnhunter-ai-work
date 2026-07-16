# Disabled Scanner Worker Boundary

This directory establishes the future scanner worker as a process separate from
the Django web process. It is not an activated scanner deployment.

The container:

- contains no Nuclei or OpenVAS binary;
- starts no network listener;
- uses `network_mode: none`;
- runs as an unprivileged user;
- is read-only with all Linux capabilities removed;
- validates the repository compatibility manifest;
- reports `blocked_execution_disabled` and exits with status `78`.

The Compose service is hidden behind the explicit
`disabled-scanner-worker` profile. Starting it still cannot scan a target.
A future milestone must add authenticated manager-to-worker transport,
container image provenance, secret-provider integration, and a separately
reviewed real runner before this boundary can accept work.
