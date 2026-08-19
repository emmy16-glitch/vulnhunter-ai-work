# Client Status and Fresh V380 APK Analysis

## React/TypeScript client

The React client foundation is present under `frontend/`. Its package defines `typecheck` and `build` scripts, but no React unit-test runner or coverage configuration is currently declared. The verification results were:

| Check | Result |
|---|---|
| TypeScript typecheck | **PASS** (`tsc --noEmit`) |
| Vite production build | **PASS** |
| Dedicated React unit tests | **Not configured** |
| React coverage artifact | **Not generated** |

The build produced the Vite bundle successfully. This establishes compile and production-bundle health, not runtime test coverage.

## Flutter/Dart client

The Flutter client foundation is present under `mobile/`, with model and resumable-upload tests under `mobile/test/`. The Dart/Flutter toolchain is not installed in this execution environment: neither `dart` nor `flutter` is on `PATH`. Consequently, `flutter analyze` and `flutter test --coverage` could not run, and no `mobile/coverage/lcov.info` artifact was produced.

| Check | Result |
|---|---|
| Dart formatter | **Unavailable in this environment** |
| Flutter analyzer | **Not run: `flutter` executable unavailable** |
| Flutter tests | **Not run: `flutter` executable unavailable** |
| Flutter coverage | **Not generated** |
| Repository Flutter tests present | `mobile/test/models_test.dart`, `mobile/test/resumable_upload_test.dart` |

The updated Dart realtime model and client preserve the normalized assessment snapshot fields and cursor state; they require the normal mobile CI environment for executable verification.

## Fresh uploaded APK analysis

The uploaded APK was `/home/ubuntu/upload/V380.apk`. Its SHA-256 is `70a48a532156cd275bbf4efdb74549153caf214d2d1be8937b66800888b3fd7c`, and its size is 262,655,303 bytes. The fresh run used job ID `mobile-v380-another-20260819` and the bounded signed worker pipeline under `/tmp/vh-v380-another-analysis`. The APK was not executed on the VulnHunter host, no external systems were contacted, and dynamic execution remained fail-closed.

| Capability | Evidence-level result | Details |
|---|---|---|
| Androguard | **PASS** | Real adapter capture completed with return code 0. |
| YARA | **PASS** | Real adapter capture completed with return code 0 and 16 candidate observations persisted. |
| JADX | **PARTIAL** | Real JADX ran against the APK, generated 41,749 files, and ended at the bounded timeout with return code 124. |
| Radare2 | **NOT RUN** | The APK contains zero native libraries, so native inspection was not applicable. |
| AAPT2, apksigner, APKiD, Apktool, Ghidra | **NOT AVAILABLE** | No approved executable was configured for this run. |
| Dynamic execution via ADB/Frida/MobSF/emulator | **BLOCKED** | Required isolated runtime identity, private MobSF policy, and exact digest-bound approval were not present. |

The signed receipt is `/tmp/vh-v380-another-analysis/spool/completed/mobile-v380-another-20260819.receipt.json` and the signed progress record is `/tmp/vh-v380-another-analysis/spool/completed/mobile-v380-another-20260819.progress.json`. The worker reached a terminal `completed` state for the bounded static workflow, but the result is intentionally not described as full APK analysis because JADX was partial and several capabilities were unavailable or inapplicable.
