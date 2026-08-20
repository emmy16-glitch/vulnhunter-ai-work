# V380 APK JADX and YARA Security Review

## Scope and evidence boundary

This review covers the real V380 APK acceptance run for SHA-256 `70a48a532156cd275bbf4efdb74549153caf214d2d1be8937b66800888b3fd7c` and the installed-tool evidence collected by VulnHunter. It is a **read-only static review**. No endpoint discovered in the APK was contacted, no APK code was executed on the VulnHunter host, and dynamic execution remained fail-closed because the required isolated approved runtime was not present.

The JADX stage was **partial**, not complete: it produced 41,748 files and terminated with timeout return code 124. Therefore, absence of a pattern in the decompiled source is not proof of absence from the APK. The conclusions below are bounded by the artifacts that were actually produced and by corroborating manifest, YARA, AAPT2, Apktool, Androguard, and signing evidence.

## Executive classification

| Indicator | Evidence level | Classification | Why it matters | Required follow-up |
|---|---|---|---|---|
| `android:usesCleartextTraffic="true"` plus app-owned `http://` endpoints | Verified configuration | **High** | The manifest explicitly permits cleartext traffic, while app-owned sources contain numerous HTTP URLs for billing, update, logging, IoT, media, and telemetry paths | Confirm whether each HTTP path is reachable in supported configurations; migrate to HTTPS or document narrowly scoped exceptions; verify network security configuration |
| 17 exported components without component permissions | Verified configuration | **Medium** | Exported activities, services, receivers, or providers can enlarge the externally reachable component surface | Review each component's intended caller, add permissions or set `exported=false` where appropriate, and test intent abuse cases in an isolated lab |
| App-owned dynamic server endpoint assignment | Evidence-required risk indicator | **Medium candidate** | `GlobalDefines.java` assigns server values received from JSON into `GlobalConfiguration.sDynamicAssign*` fields, including several HTTP-prefixed values | Trace the source response, authentication, validation, allowlisting, redirect behavior, and persistence; do not treat endpoint assignment alone as an exploit |
| WebView JavaScript bridge calls | Evidence-required candidate; bundled SDKs | **Medium candidate** | `addJavascriptInterface` calls were found in JPush, ByteDance, Google Ads, Yandex Ads, and Bigo SDK namespaces | Review bridge annotations, loaded origins, navigation policy, and SDK versions; no app-owned bridge call was found in the retained JADX tree |
| Dynamic code loading | Evidence-required candidate; bundled SDKs | **Medium candidate** | `DexClassLoader`/`PathClassLoader` references were found in Google Play services and Huawei HMS namespaces | Identify the downloaded artifact source, signature/integrity checks, storage permissions, and execution path; no app-owned loader call was found in the retained JADX tree |
| Dangerous/sensitive permissions | Informational | **Info** | Permissions increase capability but are not vulnerabilities by themselves | Map each permission to a user-facing feature and least-privilege requirement |
| Native-code surface | Not applicable | **Not observed** | The APK contains zero native libraries in this run | Radare2 and Ghidra were correctly not run; re-evaluate if another build contains native libraries |

## Verified findings

### 1. Cleartext traffic is a verified high-severity configuration finding

The manifest contains `android:usesCleartextTraffic="true"`. The app-owned decompiled sources corroborate this with a broad set of hardcoded `http://` URLs in `com.macrovideo.v380pro.defines.HttpUrlDefines`, `GlobalDefines`, and `OkHttpUtil`. Representative paths include the HTTP billing host `mapi.av380.net:8002`, update and log services under `av380.net`, IoT services on `av380.net` and `av380.cn`, and media or telemetry endpoints under `nvcam.net`.

`GlobalDefines.java` also selects between HTTPS and HTTP for the billing base URL using `GlobalConfiguration.sIsUseHttps`, and `OkHttpUtil.java` constructs a shared `OkHttpClient` and issues requests using URLs supplied by the app. This combination is stronger than a string-only match: it shows a manifest permission for cleartext and app-owned request construction that can consume HTTP URLs. The result remains a configuration finding, not proof that a particular request leaked sensitive data on a live network.

### 2. Exported components without permissions are verified configuration findings

AAPT2 and Apktool manifest analysis reported 17 exported components that do not declare a component permission. The affected surface includes app activities such as `NotificationWebViewActivity`, `LaunchActivityWithAd`, `LoginActivity`, `WXPayEntryActivity`, and `H5PayActivity`, together with exported components supplied by push, social-login, and advertising SDKs. Exported status is not automatically unsafe: some components intentionally serve deep links or provider contracts. The finding is therefore a review requirement for each component's caller and intent validation, not an exploit claim.

## App-owned risk indicator: dynamic server endpoint assignment

The strongest new app-owned code pattern from the JADX output is in `com.macrovideo.v380pro.utils.GlobalDefines` around lines 3406–3432. Values parsed from a response are concatenated with URL schemes and assigned to fields including:

- `sDynamicAssignIotOnlineBindServer`
- `sDynamicAssignIotKeyExchangeServer`
- `sDynamicAssignIotDispatchServer`
- `sDynamicAssignIotDevModelServer`
- `sDynamicAssignIotDevOTAServer`
- `sDynamicAssignIotDevOnlineServer`
- `sDynamicAssignS3SearchHost`

Several assignments explicitly prepend `http://`; others prepend `https://`. This is an **app-owned endpoint-control pattern** and should be validated as a candidate security risk. The static evidence does not establish whether the response is authenticated, whether the values are allowlisted, whether redirects are restricted, or whether the fields are persisted and reused across trust boundaries. Those questions require a controlled code-path review or a separately approved isolated dynamic test; they do not justify contacting any discovered host from this environment.

## YARA candidates verified against JADX namespaces

### WebView JavaScript bridge

The YARA scan produced ten bridge-related candidate observations distributed across seven DEX files. The retained JADX source resolves these calls to bundled third-party namespaces:

| Namespace or class family | Observed pattern |
|---|---|
| `cn.jpush.android.u.f` | Reflective `addJavascriptInterface` with the `JPushWeb` name |
| `com.bytedance.sdk.component.*` | Direct bridge installation on SDK WebViews |
| `com.google.android.gms.ads.*` and `com.google.android.gms.internal.ads.*` | Google advertising bridge installation, including `gmaSdk` |
| `com.yandex.mobile.ads.impl.*` | Yandex advertising bridge installation, including `AdPerformActionsJSI` |
| `sg.bigo.ads.*` | Bigo advertising bridge installation, including `bigossp` and `BGN_PLAYABLE` |

No `addJavascriptInterface` call was found under the app-owned `com.macrovideo.v380pro` namespace in the retained JADX tree. The app-owned tree does contain WebView wrapper and binding classes, so the absence of an app-owned bridge call should be treated as bounded by the partial decompilation rather than as a universal negative. These candidates remain **evidence required** until bridge annotations, loaded origins, SDK versions, and navigation policy are reviewed.

### Dynamic code loading

The four dynamic-loading YARA candidate observations resolve to bundled Google Play services and Huawei HMS namespaces. JADX identified `DexClassLoader` usage in `com.google.android.gms.internal.ads.zzbbc`, `zzfya`, and `zzggz`, as well as Huawei dynamic-feature code under `com.huawei.hms.feature.dynamic`. `PathClassLoader` references were likewise in Google/Huawei namespaces.

No `DexClassLoader` or `PathClassLoader` call was found under `com.macrovideo.v380pro`. The only app-owned `Class.forName` matches were fixed Android framework classes such as `android.widget.Editor` and `com.android.internal.R$dimen`, which are consistent with UI customization and are not evidence of remote code loading. The SDK findings still merit supply-chain and integrity review, but they are not app-owned dynamic-loader findings based on this evidence.

## Additional app-owned observations

The app-owned sources contain models and serialization paths for device-sharing and login data, including password and login-token fields. These matches show that sensitive data types exist in the application model; they do **not** establish plaintext storage, insecure transport, logging, or disclosure. The review should therefore avoid escalating these strings without a data-flow proof. No endpoint was contacted and no credentials were tested.

## Tool and stage status

| Stage/tool | Result | Interpretation |
|---|---|---|
| AAPT2 | Pass | Manifest/package metadata inspection completed |
| apksigner | Pass | APK signature verification completed |
| APKiD | Pass | Packaging/protector/YARA-backed identification completed |
| Apktool | Pass | Static resource and manifest decode completed after trusted framework-link materialization |
| JADX | Partial | 41,748 files produced; timeout code 124; source review is bounded |
| Androguard | Pass | DEX/manifest inspection completed in the acceptance receipt |
| YARA | Pass | Candidate observations persisted and manually correlated with JADX namespaces |
| Radare2 | Not run | APK has zero native libraries |
| Ghidra | Not run | APK has zero native libraries |
| Dynamic execution | Blocked | Fail-closed policy correctly held because an approved isolated runtime was unavailable |

The acceptance receipt `mobile-v380-installed-tools-20260819b` reports `completed`, 7 captures, and 32 candidate observations. The word **completed** refers to the bounded read-only static workflow; it does not mean that every possible APK-analysis stage ran.

## Recommended next actions

First, preserve the cleartext and exported-component findings as verified configuration observations. Second, add a bounded YARA or source-analysis rule for the `sDynamicAssign` family, but classify it as evidence-required rather than automatically as a vulnerability. Third, review the SDK bridge and loader candidates with namespace ownership, SDK versions, origin restrictions, integrity checks, and data-flow context. Finally, if dynamic evidence is needed, attach the authorized KVM-capable isolated runtime and keep the existing approval, network scope, worker isolation, and fail-closed gates intact.

## References

[Android AAPT2 documentation](https://developer.android.com/tools/aapt2) · [Android apksigner documentation](https://developer.android.com/tools/apksigner) · [APKiD v3.1.0 release](https://github.com/rednaga/APKiD/releases) · [Apktool installation guide](https://apktool.org/docs/install/) · Pinned release installation implementation: `scripts/install_mobile_release_tools.py`.
