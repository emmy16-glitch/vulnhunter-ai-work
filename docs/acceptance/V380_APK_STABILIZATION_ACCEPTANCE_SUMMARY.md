# V380.apk Stabilization Acceptance Summary

## Run identity

This acceptance run used the real `/home/ubuntu/upload/V380.apk` artifact and the same bounded signed mobile worker pipeline used by VulnHunter. The APK SHA-256 was `70a48a532156cd275bbf4efdb74549153caf214d2d1be8937b66800888b3fd7c`, the artifact size was 262,655,303 bytes, the package contained 12 DEX files and 0 native libraries, and the worker job was `mobile-v380-stabilization-20260819`.

The worker ran outside the repository under `/tmp/vh-v380-stabilization-acceptance`, with network isolation set to `process_policy`. Dynamic execution was not unlocked, no APK process was started on the VulnHunter host, and no external target discovered in APK strings was contacted.

## Capability classification

| Capability | Real APK evidence | Result | Evidence basis |
|---|---|---|---|
| Androguard | Yes | **PASS** | One signed capture, return code 0; genuine DEX/permission inspection completed. |
| YARA | Yes | **PASS** | One signed capture, return code 0; 16 candidate observations persisted. |
| JADX | Yes | **PARTIAL** | Real JADX executable ran, generated 41,711 files, and ended with return code 124 at the bounded timeout. |
| Radare2 | Yes | **NOT RUN** | The real APK contained zero native libraries, so native inspection was not applicable. |
| AAPT2 | No | **NOT AVAILABLE** | No approved executable was configured. |
| apksigner | No | **NOT AVAILABLE** | No approved executable was configured. |
| APKiD | No | **NOT AVAILABLE** | No approved executable was configured. |
| Apktool | No | **NOT AVAILABLE** | No approved executable was configured. |
| Ghidra | No | **NOT AVAILABLE** | No approved executable was configured. |
| Dynamic execution (ADB/Frida/MobSF/emulator) | No | **BLOCKED** | Disposable isolated runtime, device identity, private MobSF policy, and exact digest-bound approval were not present. |

The run produced three tool captures and nine persisted progress events. The receipt state was `completed` for the bounded static workflow, but the capability result is intentionally not described as a full APK analysis because JADX was partial and several tools were unavailable or inapplicable.

## Persisted evidence

The signed receipt was written to `/tmp/vh-v380-stabilization-acceptance/spool/completed/mobile-v380-stabilization-20260819.receipt.json`. The signed progress record was written to `/tmp/vh-v380-stabilization-acceptance/spool/completed/mobile-v380-stabilization-20260819.progress.json`. The acceptance harness unit probe passed all seven targeted worker runtime tests.

The candidate observation IDs include the real JADX capture, the Androguard permission observation, and fourteen YARA observations. Findings and candidate observations remain evidence-backed persisted objects; the acceptance run did not fabricate completion for tools that did not run.

## Safety conclusion

The static worker path remains safe and bounded. The APK was not executed on the VulnHunter host, dynamic analysis stayed fail-closed, the worker used signed job and receipt binding, and all unsupported capabilities were classified as unavailable, not run, partial, or blocked rather than presented as successful analysis.
