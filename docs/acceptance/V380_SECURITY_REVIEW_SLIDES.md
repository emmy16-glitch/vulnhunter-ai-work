# V380 Security Review — Slide Content

## Cover
V380 APK Security Review
Verified findings, app-owned endpoint inventory, and bounded acceptance status
Manus AI · 19 August 2026

## Slide 1
### The review found a real transport-control problem
- **High / verified configuration:** `android:usesCleartextTraffic="true"`.
- App-owned source corroborates the setting with **50 HTTP** and **29 HTTPS** URL string literals.
- The finding is static evidence of exposure, not a live interception demonstration.
- No APK execution and no endpoint contact occurred.

## Slide 2
### Static acceptance completed — but not every stage ran
- **7 captures · 32 candidate observations · 12 DEX files**.
- Completed: AAPT2, apksigner, APKiD, Apktool, Androguard, and YARA.
- JADX: **partial**, 41,622 generated files, timeout return code 124.
- Radare2/Ghidra: not run because V380 contains **zero native libraries**.
- Dynamic execution: **blocked fail-closed** pending an approved isolated runtime and exact approval.

## Slide 3
### 17 exported components expand the reachable app surface
- All 17 were persisted as **medium / verified_configuration** observations.
- **8 app-owned** components; **9 SDK/integration** components.
- Type mix: **13 activities, 1 service, 1 receiver, 2 providers**.
- Exported status is not automatically exploitable; each component needs caller, intent, and permission review.

## Slide 4
### App-owned entry points deserve first remediation priority
- `LaunchActivityWithAd` — launch and advertising entry.
- `NotificationWebViewActivity` — notification-linked WebView route.
- `HomePageActivity`, `LoginActivity` — primary navigation and authentication entry.
- `DeviceAlarmMessageActivity` — device alarm payload route.
- `WXPayEntryActivity`, `WXEntryActivity`, `H5PayActivity` — payment and callback routes.
- Priority checks: intent extras, deep links, authentication state, URL allowlists, callback signatures, and replay protection.

## Slide 5
### SDK components remain part of the deployed attack surface
- Facebook, LINE, and VK callback activities.
- JPush notification activities and transit activity.
- Huawei HMS push service and provider.
- MBridge network-change receiver.
- AppMetrica preload-information provider.
- Remediation may depend on SDK version, provider authority, URI grants, and upstream permission enforcement.

## Slide 6
### Cleartext paths span security-sensitive service families
- **Billing/account:** `mapi.av380.net:8002`.
- **Updates/firmware:** `updateapp.av380.net`, `ipcupdate.av380.net`.
- **Device/IoT:** `deviotcardquery.av380.net:8887`, `meshlink-relations.av380.net:9002`.
- **Logs/telemetry:** `applelog.av380.cn`, `logs.av380.net`, `logreport.nvcam.net`.
- **Content/media:** `adwscdn.av380.net`, `jfwscdn.av380.net:8001`, `demosite1.av380.net`.
- Static endpoint strings do not prove every path is reachable or active.

## Slide 7
### The endpoint inventory is broad and unevenly protected
- **50 HTTP** versus **29 HTTPS** de-duplicated app-owned URL literals.
- HTTP hosts include `av380.net`, `av380.cn`, `nvcam.net`, and an Alibaba OSS endpoint.
- HTTP references cover ad delivery, device state, logging, media, time configuration, and update metadata.
- Remediation should eliminate HTTP fallback for authenticated, update, device-control, and endpoint-discovery traffic.

## Slide 8
### Server-controlled endpoint assignment is an app-owned candidate risk
- `GlobalDefines.java` maps response values into `sDynamicAssign*` fields.
- Affected roles include IoT binding, key exchange, dispatch, device model, OTA, online service, and S3 search.
- Several assignments prepend `http://`; others prepend `https://`.
- **Evidence-required candidate:** static code does not prove response authenticity, allowlisting, redirect policy, persistence, or reachability.

## Slide 9
### YARA candidates were correlated — not overclaimed
- WebView bridge hits resolved to JPush, ByteDance, Google Ads, Yandex Ads, and Bigo namespaces.
- Dynamic-loader hits resolved to Google Play services and Huawei HMS namespaces.
- No app-owned `addJavascriptInterface`, `DexClassLoader`, or `PathClassLoader` call was found in the retained partial JADX tree.
- Because JADX timed out, absence is bounded evidence, not a universal negative.

## Slide 10
### Recommended actions preserve the safety boundary
- Replace cleartext defaults with HTTPS-only transport and narrowly scoped network-security policy.
- Review all 8 app-owned exported components; then validate SDK component authorities and versions.
- Add bounded detection for the `sDynamicAssign*` endpoint-assignment family.
- Review WebView origins, bridge annotations, SDK versions, loader integrity, and downloaded artifact provenance.
- Keep dynamic analysis fail-closed until the isolated runtime, device identity, private policy, and digest-bound approval exist.

## Slide 11
### Evidence package and conclusion
- The static workflow produced real persisted evidence and a reproducible receipt.
- Verified findings: cleartext configuration and 17 exported components without component permissions.
- Evidence-required candidates: app-owned dynamic endpoint assignment and bundled-SDK WebView/loader surfaces.
- **Conclusion:** V380 requires transport and component-surface hardening; the review is actionable without misrepresenting partial stages as full APK analysis.
- Source package: final acceptance receipt, detailed component/cleartext breakdown, JADX/YARA review, and YARA evidence notes.
