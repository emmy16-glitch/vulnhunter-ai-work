# Connection-Bound DNS Enforcement

## Purpose

This subsystem ensures that a URL approved by VulnHunter is connected to through the same bounded address decision. It removes the second, uncontrolled hostname lookup that ordinary HTTP clients may perform when opening a socket.

## Trust model

`ApprovedTarget.resolved_addresses` is the immutable outer set established during target validation. A request may use only a non-empty connection-time subset of that set.

```text
ApprovedTarget
  -> ScopedUrl validation
  -> connection-time DNS resolution
  -> subset check
  -> direct approved-IP TCP connection
  -> peer verification
  -> HTTP/TLS with original hostname
  -> ConnectionAuditEvent
```

## Hostname preservation

The transport never rewrites the request URL to an IP address. The original hostname remains responsible for:

- the HTTP `Host` header;
- TLS SNI;
- certificate hostname verification;
- application virtual-host routing.

Only the low-level TCP destination is replaced with the selected approved IP.

## Redirects and retries

Automatic redirects remain disabled. `SafeHttpClient` validates every redirect, and each resulting request receives a new connection-time resolution and a fresh socket.

Retries are implemented only across the current approved address set. An address that was not returned by the connection-time resolver, or that is not present in the immutable target set, is never attempted.

## Connection evidence

Each connection event records:

- timestamp;
- scheme, hostname, and port;
- approved current addresses;
- ordered attempts and outcomes;
- verified connected address;
- TLS server hostname when applicable;
- final connected, blocked, or error outcome.

The evidence contains no headers, cookies, credentials, query values, or response bodies.

## Deliberate performance choice

Keep-alive reuse is disabled. This costs some throughput but guarantees that every request and redirect receives an independent, current, auditable address-binding decision. VulnHunter is a bounded laboratory research tool, so correctness takes precedence over connection reuse.

## Residual boundary

The implementation covers direct HTTP and HTTPS connections. Environment proxy inheritance remains disabled. Any future proxy design must document where DNS resolution occurs, how the proxy is authorised, how target scope is preserved, and which peer address can be meaningfully verified.
