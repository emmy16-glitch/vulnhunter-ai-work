# V380 Intelligence-Layer Acceptance Summary

**Run:** `mobile-v380-final-intelligence-retry-20260819`  
**Artifact:** V380.apk  
**Artifact SHA-256:** `70a48a532156cd275bbf4efdb74549153caf214d2d1be8937b66800888b3fd7c`  
**Scope:** bounded read-only static/native workflow; dynamic analysis remained fail-closed

## Semantic result

The real receipt persisted **32 raw analysis observations** and normalized them into distinct records:

| Semantic category | Count |
|---|---:|
| Verified configuration | 18 |
| Verified security finding | 0 |
| Evidence-required candidates | 13 |
| Operational issues | 2 |
| Correlation hypotheses | 1 |
| Transport correlations | 1 |
| Exported-component surfaces | 24 |

The 18 verified configurations include the application cleartext-traffic condition and the exported-component configuration records. They do not assert exploitability. The 13 candidates preserve evidence-required status for sensitive permissions, bundled-SDK WebView/dynamic-loading surfaces, and other bounded observations. JADX’s timeout is represented as an operational/partial condition and is not a finding.

## Capability coverage

| Capability | Status | Receipt evidence |
|---|---|---|
| AAPT2 | Completed | Return code 0; output digest persisted |
| apksigner | Completed | Return code 0; output digest persisted |
| APKiD | Completed | Return code 0; output digest persisted |
| Apktool | Completed | Return code 0; output digest persisted |
| Androguard | Completed | Return code 0; output digest persisted |
| YARA | Completed | Return code 0; output digest persisted |
| JADX | Partial | Return code 124; 41,748 generated files retained by the worker |
| Radare2 | Not applicable | No native libraries discovered |
| Ghidra | Not applicable | No native libraries discovered |
| Dynamic analysis | Blocked | Approved isolated runtime unavailable; fail-closed gate preserved |

Overall coverage is `completed_with_partial_stage`: 6 completed capabilities, 1 partial, 2 not applicable, and 1 blocked. This is not presented as full APK analysis.

## Correlation and bounded negatives

The receipt includes **450 deduplicated endpoint references** and one transport correlation connecting the verified manifest cleartext policy with normalized HTTP source references. Endpoint references preserve normalized protocol, host/port where safely parseable, likely service family, ownership, reachability unknown, and all contributing source references. Duplicate literals are collapsed by normalized endpoint/protocol/service/ownership key rather than counted as independent security findings. Malformed URL literals are retained as bounded source evidence with unknown port rather than invalidating the receipt.

The receipt also persists bounded-negative language for the partial JADX review:

> No app-owned matching JavaScript bridge call was found in the retained partial source inspected; this is not whole-APK absence.

> No app-owned dynamic class-loader match was found in the retained partial source inspected; this is not whole-APK absence.

## Safety acceptance

No APK was executed on the VulnHunter host. No endpoint discovered in APK strings was contacted. No dynamic-analysis prerequisite was bypassed. The worker remained read-only and isolated, the exact artifact digest remained authoritative, and the temporary receipt/workspace were not added to version control.
