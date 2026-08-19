# V380 YARA Evidence Review Notes

Source: fresh signed receipt `/tmp/vh-v380-another-analysis/spool/completed/mobile-v380-another-20260819.receipt.json` for job `mobile-v380-another-20260819` and artifact SHA-256 `70a48a532156cd275bbf4efdb74549153caf214d2d1be8937b66800888b3fd7c`.

The receipt contains 16 candidate observations: one JADX operational-failure observation, one Androguard sensitive-permissions observation, twelve YARA observations from extracted DEX content, and three YARA observations mapped to JADX output source paths.

The YARA ruleset SHA-256 is `0c5a74ffe624f9c7bef86745a6ce598517fa6a85f8533c609f60f1c8cf90bbde`. All YARA observations are `evidence_required`, not verified findings.

YARA distribution:

| Rule | Count | Severity | Status |
|---|---:|---|---|
| `android_webview_javascript_bridge_surface` / CWE-749 | 10 | Medium | Evidence required |
| `android_remote_dynamic_code_loading_surface` / CWE-494 | 4 | Medium | Evidence required |
| `android_embedded_private_key` | 0 | — | No match |
| `android_cloud_access_key_identifier` | 0 | — | No match |

The WebView bridge rule requires both `addJavascriptInterface` and `setJavaScriptEnabled`; its matches occur in extracted DEX paths `classes3.dex`, `classes8.dex`, `classes6.dex`, `classes4.dex`, `classes11.dex`, `classes5.dex`, `classes9.dex`, plus JADX source paths `cn/jpush/android/u/f.java`, `com/bytedance/sdk/component/icm/on.java`, and `com/google/android/gms/internal/ads/zzclc.java`. The three named JADX source paths are bundled third-party namespaces, so the current evidence establishes an attack surface in packaged code but does not attribute it to V380 application-owned code.

The remote dynamic-code-loading rule requires `DexClassLoader` or `PathClassLoader` plus an `http://` or `https://` string. Four observations occur in extracted DEX paths `classes8.dex`, `classes6.dex`, `classes5.dex`, and `classes7.dex`, with 13–40 raw string matches per observation. This establishes a candidate loading/network surface, not proof that remote code is fetched or executed, because YARA does not prove control-flow linkage, origin trust, signature validation, or runtime reachability.

The Androguard observation reports sensitive Android permissions in `AndroidManifest.xml` with `mobile-dangerous-permissions`, severity `info`, and status `evidence_required`. The JADX observation is operational only: real JADX generated 41,749 files before bounded timeout and returned 124; it is not a vulnerability finding.

Safety classification: no candidate is promoted to a verified finding from YARA alone; no APK execution, endpoint contact, or dynamic-analysis unlock occurred.


## Installed-tool acceptance

The following static tools were installed and verified without executing the APK:

| Tool | Source/version | Verification |
|---|---|---|
| AAPT2 | Ubuntu `android-sdk-build-tools` 29.0.3 package; executable `/usr/lib/android-sdk/build-tools/debian/aapt2` | Real `aapt2 dump badging` completed successfully |
| apksigner | Ubuntu Android build-tools package; executable `/usr/lib/android-sdk/build-tools/debian/apksigner` | Real `apksigner verify --verbose --print-certs` completed successfully |
| APKiD | Official `rednaga/APKiD` tag `v3.1.0`, commit `3db7bb9c57166b63e8855940b75966e62a6cf1ed` | Pinned YARA rules compiled into the installed package; real V380 scan completed successfully |
| Apktool | Ubuntu `apktool` 2.7.0 package | Real static decode completed successfully after the trusted system framework link was materialized into the isolated worker home |
| Ghidra | Official pinned Ghidra 12.1 release, SHA-256 `aa5cbcbbf48f41ca185fce900e19592f1ade4cd5994eb6e0ede468dac8a6f302` | Installed and discovered by worker preflight; not run because V380 contains zero native libraries |

The installed-tool acceptance job was `mobile-v380-installed-tools-20260819b`. It produced 7 captures and 32 observations: JADX remained partial with 41,748 generated files and timeout return code 124; AAPT2, apksigner, APKiD, Apktool, Androguard and YARA completed; Radare2 and Ghidra were correctly planned but not run due to zero native libraries. Manifest analysis added a verified cleartext-traffic configuration and 17 exported components without component permissions. These are persisted configuration observations, not exploit demonstrations.

Official references used for installation review: [Android AAPT2 documentation](https://developer.android.com/tools/aapt2), [Android apksigner documentation](https://developer.android.com/tools/apksigner), [APKiD v3.1.0 releases](https://github.com/rednaga/APKiD/releases), [Apktool install guide](https://apktool.org/docs/install/), and the repository’s pinned Ghidra installer in `scripts/install_mobile_release_tools.py`.
