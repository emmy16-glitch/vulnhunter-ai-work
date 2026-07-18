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

## Isolated worker

The worker consumes one signed, immutable and expiring job from a local spool. Before starting a process it independently verifies:

- HMAC signature and invocation digest;
- job and plan expiry;
- authorization and exact approval binding;
- target, protocol, port and address pins;
- passive profile, rate and concurrency limits;
- scanner, adapter and template versions;
- template file hashes;
- approved evidence path and worker-local activation policy.

The passive pilot accepts one literal private address, one reviewed passive template, rate limit `1` and concurrency `1`. It runs as a separate unprivileged process boundary with a minimal environment, fixed arguments, process-group cancellation, bounded output files and operating-system resource limits.

## Shared protocol

Scanner protocol `1.0` currently contains:

- `nuclei-controlled-harness` — manager harness plus an independently activated passive worker pilot;
- `mobile-analysis-planned-adapter` — shared contract for the separate static and future disposable dynamic workers.

The protocol is tool-independent. A future scanner must reuse the same authorization, approval, signed-job, evidence, redaction, verification and candidate-finding rules rather than adding a second control plane.

## Control ownership

| Responsibility | Manager | Worker |
|---|---:|---:|
| Target authorization | owns | revalidates |
| Human approval | owns | revalidates |
| Plan digest | creates | verifies |
| Version/template policy | defines | verifies installed state |
| Scanner process | never | owns |
| Cancellation | issues | enforces |
| Evidence hashing | verifies | produces bounded artifacts |
| Deterministic verification | owns | never |
| Finding confirmation and release | human workflow | never |

## Queue and recovery

The signed spool has pending, processing, completed, failed and cancellation areas. Jobs are written atomically with restrictive permissions. Replays and duplicate job IDs are rejected. A pending Stop request moves the job to a terminal cancelled receipt; a claimed or running job receives a cooperative cancellation marker and execution-store cancellation request.

On worker restart, stranded processing jobs and unfinished execution records recover fail-closed. The worker never assumes a scanner process survived the restart.

## Activation rule

Code readiness is not operational activation. The pilot remains disabled until an operator provides the pinned executable, reviewed policy, owner-private signing key, private-lab authorization and isolated runtime. Browser input cannot enable it.
