# ADR-0012: Connection-bound DNS scope enforcement

## Status

Accepted.

## Context

VulnHunter already validated target DNS results during target approval and again before derived URLs and redirects. The default HTTP stack could still perform another hostname lookup while opening the TCP socket. That left a time-of-check/time-of-use gap: validation and connection were separate decisions.

A safe fix must bind the socket to an approved IP address without replacing the original hostname in the request. Replacing the URL hostname with an IP would break HTTP virtual hosting, TLS SNI, and certificate hostname verification.

## Decision

The default safe HTTP client uses `PinnedAsyncTransport`, backed by a custom HTTPcore network backend.

For every request and redirect hop, the transport:

1. verifies the request scheme, hostname, and port against `ApprovedTarget`;
2. resolves the original hostname immediately before opening a connection;
3. canonicalises the current IPv4/IPv6 results;
4. requires the current result to be a non-empty subset of the immutable approved address set;
5. gives each approved IP directly to the TCP backend, so the backend performs no hostname lookup;
6. verifies the connected peer address;
7. retains the original hostname in the HTTP request and TLS `server_hostname`;
8. records immutable connection evidence;
9. disables keep-alive reuse so each request receives an independent binding decision.

Retries may rotate only through the approved current address set. HTTPcore's automatic connection retries remain disabled.

Caller-provided transports remain supported for deterministic tests. The safe client exposes whether connection pinning is active and exposes connection audit events when the pinned transport is used.

## Consequences

### Positive

- closes the application-level DNS rebinding time-of-check/time-of-use gap;
- preserves virtual-host routing and TLS certificate validation;
- supports IPv4 and IPv6;
- creates auditable evidence of validated, attempted, and connected addresses;
- keeps redirect handling inside the existing manual scope-validation flow;
- fails closed on empty, malformed, changed, or unverifiable address results.

### Trade-offs

- disabling connection reuse reduces throughput;
- HTTPcore becomes an explicit runtime dependency because HTTPX does not expose a public custom-resolver hook;
- proxy support remains disabled because proxies introduce a separate DNS and routing trust boundary;
- application-level pinning does not defend against a compromised operating system, privileged socket interception, or malicious trust stores.

## Verification

The regression suite covers Host preservation, TLS SNI, DNS changes between validation and connection, approved-address-only retries, peer mismatch, direct IP targets, IPv6, independent connections, connection evidence, safe-client integration, and a real loopback socket path.
