# ADR-0019: Governed Android APK analysis before execution

- **Status:** Accepted
- **Date:** 2026-07-11
- **Owner:** Emmanuel Okunlola

## Context

VulnHunter must be able to accept an Android APK, inspect it with several free
security tools, correlate evidence, and prepare controlled runtime validation.
An APK is untrusted executable content. Treating it like an ordinary document
would expose the host, leak data, and make tool output difficult to audit.

## Decision

APK handling uses a content-addressed artifact boundary before any tool is
planned. Intake must:

1. accept only an `.apk` filename and bounded byte stream;
2. calculate SHA-256 while storing the upload;
3. validate the ZIP-compatible archive structure;
4. reject traversal paths, symlink entries, excessive entry counts, excessive
   uncompressed size, and unsafe compression ratios;
5. require `AndroidManifest.xml` and at least one `classes*.dex` entry;
6. store the original APK read-only under its digest;
7. record DEX and native-library inventory without executing the APK.

Static analysis may be planned through fixed shell-free adapters for Android
SDK metadata tools, Apktool, JADX, APKiD, YARA, and radare2. Androguard, MobSF,
Ghidra, ADB, and Frida use dedicated connector contracts where a normal fixed
CLI plan would be incomplete or unsafe.

Dynamic analysis is a separate stage. It requires:

- an explicit human approval bound to the exact action manifest;
- an isolated disposable Android runtime reference;
- an approved Android device or emulator reference;
- no personal accounts, credentials, or unrelated data in the runtime;
- restricted and recorded network behaviour;
- evidence preservation and automatic stop on policy or integrity failure.

The uploaded APK is never executed directly on the VulnHunter host. Automatic
repacking, signing, persistence, or arbitrary instrumentation scripts are not
part of this decision.

## Consequences

- Mobile analysis is reproducible and tied to an immutable artifact digest.
- Agents can choose the correct static, native, and dynamic tools without
  receiving an unrestricted shell.
- Dynamic validation remains unavailable until an isolated runtime and exact
  approval exist.
- Tool binaries, emulator images, connectors, and rulesets are installed or
  activated only through later reviewed operational changes.

## Verification

Required tests cover archive traversal rejection, content-addressed storage,
artifact digest binding, mobile planner tool selection, connector-only dynamic
tools, decoded manifest observations, and role-registry validation.
