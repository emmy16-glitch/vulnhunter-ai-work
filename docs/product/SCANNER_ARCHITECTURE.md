# Scanner Manager and Worker Architecture

VulnHunter separates scanner governance from scanner execution.

The Django application is the manager. It owns authorization, scope, planning,
approval, audit, evidence trust, and finding lifecycle. It must not construct
arbitrary scanner commands or own long-running scanner subprocesses.

A future worker will own scanner processes in an isolated boundary. It may
consume only versioned, immutable requests produced after manager-side
revalidation. The worker cannot grant authorization, expand scope, approve its
own job, or publish a finding.

## Shared protocol

All adapters implement scanner protocol `1.0`:

- `nuclei-controlled-harness` — implemented, production execution blocked;
- `openvas-planned-adapter` — planned, no Greenbone process connected;
- `mobile-analysis-planned-adapter` — planned, no APK execution connected.

This interface is intentionally tool independent. Adding OpenVAS or mobile
analysis must not add a second authorization system or bypass existing
approval, evidence, redaction, and candidate-finding rules.

## Control ownership

| Responsibility | Manager | Worker |
|---|---:|---:|
| Target authorization | yes | verify only |
| Human approval | yes | verify only |
| Plan digest | create and verify | verify only |
| Version/feed policy | define | verify installed state |
| Scanner process | no | future only |
| Cancellation decision | issue | enforce |
| Evidence hashing | verify | produce bounded artifacts |
| Finding confirmation | human workflow | never |

## Activation rule

A scanner adapter being present in the registry means only that its contract is
known. It does not mean the scanner is installed, reachable, approved, or
allowed to run. `execution_enabled=false` remains authoritative.
