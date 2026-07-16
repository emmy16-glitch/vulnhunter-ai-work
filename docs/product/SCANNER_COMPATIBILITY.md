# Scanner Compatibility Matrix

The source of truth is
`config/security_tools/scanner_compatibility.json`. Missing versions are
intentional blockers, not requests to install the latest release.

<!-- scanner-compatibility:start -->

| Scanner | Adapter | Adapter version | Engine | Feed | Status | Deployment |
|---|---|---:|---:|---:|---|---|
| mobile_analysis | mobile-analysis-planned-adapter | 0.1.0 | not selected | not selected | planned | disabled |
| nuclei | nuclei-controlled-harness | 1.0.0 | v3.11.0 | v10.4.5 | harness_only | isolated_container |
| openvas | openvas-planned-adapter | 0.1.0 | not selected | not selected | planned | disabled |

<!-- scanner-compatibility:end -->

The Nuclei template-manifest file is content addressed in the compatibility
manifest. The reviewed repository manifest remains empty, so the version pin
does not authorize a scan.
