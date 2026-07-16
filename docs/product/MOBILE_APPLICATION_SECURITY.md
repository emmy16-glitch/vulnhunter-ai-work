# Mobile Application Security

## Product intent

An authorised operator can upload an Android APK and ask VulnHunter to prepare
a structured vulnerability assessment. The agent inspects the artifact record,
selects the necessary tools, creates exact action manifests, and builds a
durable task graph. It does not require the operator to manually request JADX,
Apktool, APKiD, or each later analysis stage.

## Upload boundary

The web page at `/mobile-analysis/` stores an APK only after archive and size
validation. The stored record includes:

- content SHA-256 and stable artifact ID;
- original filename and content-addressed path;
- archive entry and uncompressed-size totals;
- Android manifest and DEX inventory;
- native `.so` library and ABI inventory.

No tool, emulator, connector, or model is started by upload.

## Agent-selected profiles

### Static APK analysis

The planner can select:

1. `apksigner` for signature and certificate metadata;
2. `aapt2` for package, SDK, permission, and resource metadata;
3. APKiD for compiler, packer, protector, and obfuscation indicators;
4. Apktool for manifest, resource, and smali decoding;
5. JADX for Java-like source recovery;
6. Androguard through a dedicated Python connector contract;
7. YARA through an explicitly selected local ruleset.

### Static and native analysis

When native libraries are present, the planner adds read-only `rabin2`
inspection and a separately approved Ghidra headless connector plan.

### Dynamic emulator analysis

MobSF, ADB, and Frida are connector-only and require all of the following:

- an isolated disposable emulator or device runtime;
- exact-action human approval;
- a bounded timeout and evidence budget;
- explicit device identity;
- no execution on the VulnHunter host;
- stop and evidence preservation on any policy failure.

### Full assessment and retest

A full profile sequences static, native, and dynamic stages. Retest repeats only
checks relevant to a recorded remediation claim.

## Candidate findings

The decoded manifest analyser can conservatively identify candidate conditions
such as:

- debuggable applications;
- explicit cleartext traffic permission;
- backup enabled;
- exported components without a component permission;
- high-impact requested permissions.

These are observations, not automatically confirmed vulnerabilities. Tool
results are correlated, deduplicated, and remain candidates until independent
verification establishes reachability and impact.

## Safety and privacy

- Uploaded APKs are untrusted executable artifacts.
- The agent receives fixed adapters and typed requests, not an arbitrary shell.
- Cloud model routing must not receive APK source, private endpoints, tokens,
  raw findings, or unpublished evidence without a separately approved privacy
  decision.
- No automatic APK modification, repacking, signing, or persistence occurs.
- Dynamic traffic capture and instrumentation output are treated as sensitive
  evidence.
