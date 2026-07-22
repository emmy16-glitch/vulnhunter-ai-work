# Scanner Manager and Worker Architecture

VulnHunter separates governance from scanner execution.

## Manager

The Django application owns:

- operator identity and role policy;
- target authorization and address pins;
- exact assessment planning;
- plan digest and expiry;
- human approval;
- signed worker-job creation;
- cancellation decisions;
- evidence trust, verification, review and release state.

The manager does not accept arbitrary scanner arguments and does not own long-running scanner subprocesses.

## Signed spool

The manager writes one immutable, HMAC-signed and expiring job to an owner-controlled
spool. Pending, processing, completed, failed and cancellation areas are separate.
Jobs are written atomically with restrictive permissions. Duplicate job IDs,
replays, invalid signatures and expired jobs are rejected.

## Local isolated worker

The local worker consumes one signed job and independently verifies:

- HMAC signature and invocation digest;
- job and plan expiry;
- authorization and exact approval binding;
- target, protocol, port and address pins;
- passive profile, rate and concurrency limits;
- scanner, adapter and template versions;
- template file hashes;
- approved evidence path and worker-local activation policy.

The passive pilot accepts one literal private address, one reviewed passive
template, rate limit `1` and concurrency `1`. It runs as a separate unprivileged
process boundary with a minimal environment, fixed arguments, process-group
cancellation, bounded output files and operating-system resource limits.

## Restricted remote worker transport

Milestone 33 adds an optional transport for environments where the manager host
cannot run the pinned scanner binary. The signed spool and all governance remain
with the manager. Only the fixed scanner process moves to a separately restricted
owned host.

```text
Django manager
→ signed local spool
→ guest worker revalidation
→ dedicated SSH identity with strict host-key pinning
→ forced host command
→ fixed Nuclei v3.8.0 invocation against a loopback transport target
→ bounded structured response with genuine digests
→ guest evidence and verification pipeline
```

The client sends a typed JSON request, never shell text. The host forced command
accepts no arbitrary command, target, template, flag, header, cookie, credential,
proxy or environment value. It independently verifies the owner-private host
policy, executable, engine version, template digest, target mapping, freshness,
replay state, timeout and candidate limits.

The dedicated SSH key is installed with a forced command and with agent,
forwarding, PTY, user-RC and X11 disabled. The installer uses no sudo and preserves
unrelated `authorized_keys` entries.

The remote response is bound to the request digest, worker identity, engine pin and
template digest. Zero candidate observations is a successful completed scan. The
response contains sanitized candidate metadata only; it does not return raw
headers, bodies, cookies, credentials or unrestricted process output.

## Shared protocol

Scanner protocol `1.0` currently contains:

- `nuclei-controlled-harness` — manager harness plus local or restricted remote passive worker;
- `mobile-analysis-planned-adapter` — shared contract for the separate static and future disposable dynamic workers.

The protocol is tool-independent. A future scanner must reuse the same
authorization, approval, signed-job, evidence, redaction, verification and
candidate-finding rules rather than adding a second control plane.

## Control ownership

| Responsibility | Manager | Guest worker | Host forced command |
|---|---:|---:|---:|
| Target authorization | owns | revalidates | exact policy match |
| Human approval | owns | revalidates | never owns |
| Plan digest | creates | verifies | request binding only |
| Version/template policy | defines | verifies | verifies installed state |
| Scanner process | never | local mode only | remote mode only |
| Cancellation | issues | enforces and disconnects | terminates process group |
| Evidence hashing | verifies | produces bounded artifacts | returns structured digest |
| Deterministic verification | owns | pipeline only | never |
| Finding confirmation and release | human workflow | never | never |

## Queue and recovery

On worker restart, stranded processing jobs and unfinished execution records
recover fail-closed. The worker never assumes a scanner process survived the
restart. A pending Stop request moves the job to a terminal cancelled receipt; a
claimed or running job receives a cooperative cancellation marker and execution-store
cancellation request.

The remote host also records each scan request digest in an owner-private replay
directory before process execution. Repeating the same scan request is rejected.

## Activation rule

Code readiness is not machine activation. The source defaults remain fail-closed.
For the intended private laboratory, the operator must create owner-private local
policies, set `enabled=true`, install the restricted key, restore the private port
forwards after restart, pass readiness verification, and then enable signed-job
enqueue. Browser input cannot perform any of these steps.

See `docs/setup/REMOTE_NUCLEI_WORKER.md`.
