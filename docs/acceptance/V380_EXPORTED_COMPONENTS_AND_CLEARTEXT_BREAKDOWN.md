# V380 Exported Components and Cleartext Traffic Breakdown

**Artifact examined:** V380 APK, SHA-256 `70a48a532156cd275bbf4efdb74549153caf214d2d1be8937b66800888b3fd7c`. This analysis is based on the final read-only static acceptance receipt, the manifest decode, and the retained partial JADX source inventory. No APK code was executed, and no host named below was contacted. The final acceptance state was `completed` for the bounded static workflow, not for every possible analysis stage.[1]

> **Interpretation rule:** “Without component permission” is a verified manifest configuration condition. It means that the component did not declare a manifest component permission in the evidence examined. It does **not** by itself prove that a component is exploitable; reachability, intent validation, data exposure, and the caller’s effective permissions must be assessed separately.

## 1. Exported components without component permissions

The final receipt contains **17 medium-severity `verified_configuration` observations** for exported components with no component permission.[1] Eight belong to the `com.macrovideo.v380pro` application namespace; nine are bundled SDK or platform-integration components. The purpose column is inferred from the fully-qualified class name and should be confirmed by reviewing each component’s manifest intent filters and implementation.

| # | Component | Type | Ownership classification | Inferred route or responsibility | Evidence status | Review focus |
|---:|---|---|---|---|---|---|
| 1 | `com.macrovideo.v380pro.activities.LaunchActivityWithAd` | Activity | App-owned | Launch/advertising entry route | Verified configuration | Validate intent extras, deep-link routing, authentication handoff, and whether it should remain externally reachable. |
| 2 | `com.macrovideo.v380pro.activities.NotificationWebViewActivity` | Activity | App-owned | Notification-linked WebView route | Verified configuration | Restrict untrusted intents and URLs; review URL allowlisting, JavaScript settings, and navigation handling. |
| 3 | `com.macrovideo.v380pro.activities.HomePageActivity` | Activity | App-owned | Main/home screen entry route | Verified configuration | Confirm whether exported entry is required; verify session and deep-link state handling. |
| 4 | `com.macrovideo.v380pro.activities.LoginActivity` | Activity | App-owned | Login entry route | Verified configuration | Confirm it accepts only intended callbacks; validate redirect, account-switch, and post-login navigation parameters. |
| 5 | `com.macrovideo.v380pro.activities.DeviceAlarmMessageActivity` | Activity | App-owned | Device-alarm message route | Verified configuration | Validate device identifiers, message payloads, and any privileged navigation triggered by an external intent. |
| 6 | `com.macrovideo.v380pro.wxapi.WXPayEntryActivity` | Activity | App-owned integration | WeChat Pay callback entry | Verified configuration | Confirm callback origin validation, signature/transaction checks, and replay protection. |
| 7 | `com.macrovideo.v380pro.wxapi.WXEntryActivity` | Activity | App-owned integration | WeChat authentication/share callback entry | Verified configuration | Verify state/nonce binding and reject unsolicited callback payloads. |
| 8 | `com.macrovideo.v380pro.activities.H5PayActivity` | Activity | App-owned | H5/Web payment route | Verified configuration | Apply strict URL/origin policy and validate payment parameters before handling completion callbacks. |
| 9 | `com.facebook.CustomTabActivity` | Activity | Bundled Facebook SDK | Custom-tab browser handoff | Verified configuration | Retain only if required; review the embedded SDK version and browser redirect configuration. |
| 10 | `com.linecorp.linesdk.auth.internal.LineAuthenticationCallbackActivity` | Activity | Bundled LINE SDK | LINE authentication callback | Verified configuration | Confirm current SDK version and correct redirect/state validation. |
| 11 | `com.vk.id.internal.auth.RedirectUriReceiverActivity` | Activity | Bundled VK ID SDK | VK redirect URI callback | Verified configuration | Confirm expected scheme/host and OAuth state validation. |
| 12 | `cn.jpush.android.service.JNotifyActivity` | Activity | Bundled push SDK | Notification/push presentation route | Verified configuration | Review SDK patch level and ensure payload-driven navigation is constrained. |
| 13 | `cn.android.service.JTransitActivity` | Activity | Bundled push-related namespace | Transit/notification handoff route | Verified configuration | Identify owning dependency, then validate intent and notification payload handling. |
| 14 | `com.huawei.hms.support.api.push.service.HmsMsgService` | Service | Bundled Huawei Mobile Services | Huawei push-message service | Verified configuration | Confirm intended service export and source/permission checks supplied by the current HMS SDK. |
| 15 | `com.mbridge.msdk.foundation.same.broadcast.NetWorkChangeReceiver` | Receiver | Bundled MBridge advertising SDK | Network-change event handling | Verified configuration | Confirm Android-version behavior and whether an external broadcast can influence SDK state. |
| 16 | `io.appmetrica.analytics.internal.PreloadInfoContentProvider` | Provider | Bundled AppMetrica analytics SDK | Analytics/provider initialization | Verified configuration | Review provider authorities, URI permissions, and whether external queries or mutations are possible. |
| 17 | `com.huawei.hms.support.api.push.PushProvider` | Provider | Bundled Huawei Mobile Services | Huawei push-provider integration | Verified configuration | Verify provider authority, read/write grants, and the upstream HMS security model. |

The app-owned items deserve priority because the V380 application controls their code and exported contract. The SDK-owned items should be retained in the review queue because component exposure is also part of the deployed app surface; however, attribution, patching, and remediation may depend on the relevant third-party SDK version rather than V380 application code.

### Recommended component-validation sequence

The next safe step is a code and manifest review, not external interaction. For each app-owned activity, inspect the `android:exported` declaration, intent filters, `getIntent()` handling, accepted extras, authentication checks, and downstream sensitive actions. For the two app-owned Web/H5/payment routes, treat URL and callback validation as highest priority. For content providers, inspect the authority, `grantUriPermissions`, exported read/write methods, and any permission enforcement. Controlled runtime verification would require the pre-existing isolated, authorized, digest-bound dynamic-analysis process; it is not unlocked by this static finding.

## 2. Cleartext traffic configuration and app-owned endpoint inventory

The manifest has a **high-severity verified configuration finding**: `android:usesCleartextTraffic="true"`.[1] This setting permits cleartext network traffic at the application level unless a narrower network-security policy or code path imposes additional constraints. The retained partial JADX output corroborates the configuration with app-owned `http://` string literals and request-building code in `HttpUrlDefines`, `GlobalDefines`, and `OkHttpUtil`.[2]

The source inventory identified **79 de-duplicated app-owned URL string literals: 50 `http://` and 29 `https://`**. These are static source references, not an assertion that all endpoints are reachable or used in the current product version. One HTTPS literal appears malformed (`jfwscdn.av380.netjfwscdn.av380.net`); it is preserved only as a source-quality observation and was not treated as a routable endpoint.

| Service family | Representative cleartext hosts or paths | Static indication | Security relevance |
|---|---|---|---|
| Billing/account | `mapi.av380.net:8002` | HTTP billing base is present alongside HTTPS alternatives | Review whether authenticated requests or account data can traverse the HTTP branch. |
| Update/firmware | `updateapp.av380.net/updateApp/*`; `ipcupdate.av380.net/state.php` | Update checking, history, log upload, and firmware-status strings use HTTP | Prioritize integrity and transport review because update metadata can influence user decisions or update behavior. |
| Device/IoT configuration | `deviotcardquery.av380.net:8887`; `meshlink-relations.av380.net:9002`; `nfmnclistatus.av380.net:8080`; `hscsearch.av380.net:8080` | Device card, relationship, online-status, and search paths are represented with HTTP | Assess whether device IDs, service endpoints, or routing metadata can be modified or observed on hostile networks. |
| Logging/telemetry | `applelog.av380.cn:8866`; `logs.av380.net:9191`; `logreport.nvcam.net` | App log and reporting URLs use HTTP | Review payload content and minimize telemetry over cleartext transport. |
| Advertising/content | `ad.nvdvr.cn`; `adwscdn.av380.net`; `promotionad.nvcam.net`; `adstatistics.av380.net` | Ad, web content, promotion, rating, and statistics paths use HTTP | Constrain navigation and content rendering, especially for any path displayed in WebViews. |
| Media/user content | `jfwscdn.av380.net:8001`; `demosite1.av380.net`; `babymusic.av380.net` | Playback, video-square, and music-content references use HTTP | Review whether content is WebView-rendered or parsed with privileged context. |
| Configuration/time/other | `timezonesel.nvcam.net`; `as560.av380.cn`; `asjf1.av380.cn:8083`; `oss-cn-shenzhen.aliyuncs.com` | Time-zone, device-grid, battery, and object-storage URLs use HTTP | Validate payload integrity and avoid treating untrusted response values as control data. |

The app-owned `GlobalDefines` code also assigns values parsed from a response into `sDynamicAssign*` fields for IoT online binding, key exchange, dispatch, device model, OTA, online-server, and S3-search services. Several assignments prepend `http://`; others prepend `https://`.[2] This is an **evidence-required app-owned endpoint-control pattern**, not a verified exploit: the static evidence does not establish whether the source response is authenticated, values are allowlisted, redirects are constrained, or the fields are used on a sensitive request path.

### Risk statement and remediation priority

Cleartext transport can enable passive observation or on-path modification when an affected request uses an untrusted network. The severity is driven by the verified manifest setting plus the app-owned HTTP inventory, not by a live interception demonstration. The remediation sequence is to set secure defaults at the manifest and network-security-config levels, migrate applicable endpoints to HTTPS, prevent HTTP fallback for authenticated, update, device-control, or endpoint-discovery traffic, and validate dynamically assigned hosts against a strict scheme and allowlist policy. A controlled test should verify transport enforcement only inside the authorized isolated runtime.

## 3. Final static acceptance status

The final durable-policy job, `mobile-v380-durable-installed-20260819-final`, completed its bounded read-only workflow with **7 captures and 32 candidate observations**.[1] AAPT2, apksigner, APKiD, Apktool, Androguard, and YARA completed. JADX generated 41,622 files but timed out with return code 124, so its result is correctly **partial**, not a completed decompilation. Radare2 and Ghidra were not run because the APK contained zero native libraries. Dynamic execution remained blocked by the existing fail-closed requirements for an approved isolated runtime.[1] [3]

| Capability | Final status | Interpretation |
|---|---|---|
| Manifest/package inspection | Completed | AAPT2 and Apktool evidence supported the verified configuration findings. |
| Signing inspection | Completed | apksigner inspection ran read-only. |
| APK identification and static rules | Completed | APKiD and YARA ran; YARA candidates remain evidence-required until code-path validation. |
| Java decompilation | Partial | JADX output is useful corroboration but cannot support whole-APK absence claims. |
| Native-code analysis | Not run | No native libraries were present. |
| Dynamic/emulator analysis | Blocked | No APK execution occurred; the safety gate was preserved. |

## Evidence references

[1] [Final durable installed-tools acceptance receipt](https://github.com/emmy16-glitch/vulnhunter-ai-work/blob/feature/reference-apk-workspace-ui/docs/acceptance/V380_durable_installed_tools_acceptance_receipt.json)

[2] [V380 JADX/YARA security review](https://github.com/emmy16-glitch/vulnhunter-ai-work/blob/feature/reference-apk-workspace-ui/docs/acceptance/V380_JADX_SECURITY_REVIEW.md)

[3] [V380 YARA evidence-review notes](https://github.com/emmy16-glitch/vulnhunter-ai-work/blob/feature/reference-apk-workspace-ui/docs/acceptance/V380_YARA_EVIDENCE_REVIEW_NOTES.md)
