# Governed Security Operations

## What this milestone adds

VulnHunter now has an implementation foundation for coordinating real free
security tools through bounded adapters:

- Nmap
- ProjectDiscovery httpx
- Nuclei
- OWASP ZAP
- testssl.sh
- Trivy
- Semgrep Community Edition
- Greenbone Community Edition
- OWASP Amass
- ffuf
- sqlmap
- Metasploit Framework

The tool registry is not an unrestricted terminal. Each direct adapter builds a
fixed argument vector and executes with `shell=False`. Tool output belongs
inside the governed evidence root and receives cryptographic provenance.

## Approval Centre

Consequential and sensitive actions create persistent requests bound to the
exact action-manifest SHA-256. A human chooses one of:

1. Approve once
2. Approve with conditions
3. Request more information
4. Propose a safer alternative
5. Deny and continue safely
6. Deny and stop the run

Approved requests expire and can be consumed once. Viewing a request is not
approval. The requester cannot decide or consume its own request. Conditional
approvals remain non-executable until a dedicated condition validator confirms
every recorded condition.

## Advanced assessment profiles

- Deep Discovery
- Active Assessment
- Exploitability Validation
- Privileged Environment
- Attack-Path Simulation
- Remediation Retest

Profiles build ordered task graphs and action manifests. They do not silently
activate tools. Each stage still needs valid authorization, scope, policy,
limits, and approval.

## Owner break-glass boundary

The owner contracts represent short-lived grants and root-broker requests. They
never store or request the owner’s sudo password. There is no `sudo bash`, no
arbitrary command string, and no hidden bypass of authorization or evidence.

## Disabled-by-default runtime

`config/security_tools/runtime.json` keeps every external execution switch
false. Even an explicit code-level enablement requires a pre-execution
authorization gate and a command plan issued by the same executor instance. The
milestone installer does not download a tool, run a scan, enable a connector,
use a model provider, or create a credential.

## Local verification

```bash
python -m pytest -q \
  tests/unit/test_governed_actions.py \
  tests/unit/test_approval_centre.py \
  tests/unit/test_security_tool_governance.py \
  tests/unit/test_evidence_store.py \
  tests/unit/test_taskgraph.py \
  tests/unit/test_advanced_assessment.py \
  tests/unit/test_provider_privacy_gate.py \
  tests/unit/test_owner_privilege_contract.py

python -m ruff check \
  vulnhunter/actions \
  vulnhunter/approvals \
  vulnhunter/security_tools \
  vulnhunter/evidence \
  vulnhunter/taskgraph \
  vulnhunter/providers \
  vulnhunter/owner \
  vulnhunter/advanced \
  vulnhunter/web/operations_views.py

python -m compileall -q vulnhunter
VULNHUNTER_WEB_SECRET_KEY=local-check-secret python manage.py check
git diff --check
```

## Android APK analysis extension

The security-tool registry also contains typed local-artifact and Android-device
target kinds. Mobile agents can plan JADX, Apktool, apksigner, aapt2, APKiD,
YARA, Androguard, MobSF, radare2, Ghidra, ADB, and Frida stages against a
content-addressed APK record. See `MOBILE_APPLICATION_SECURITY.md` for the APK
upload boundary, static workflow, isolated dynamic workflow, and finding
confidence rules.
