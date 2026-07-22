# Scanner Compatibility Matrix

The source of truth is
`config/security_tools/scanner_compatibility.json`. Missing versions are
intentional blockers, not requests to install the latest release.

<!-- scanner-compatibility:start -->

| Scanner | Adapter | Adapter version | Engine | Feed | Status | Deployment |
|---|---|---:|---:|---:|---|---|
| mobile_analysis | mobile-analysis-planned-adapter | 0.1.0 | not selected | not selected | planned | disabled |
| nuclei | nuclei-controlled-harness | 1.1.0 | v3.8.0 | v10.4.5 | harness_only | isolated_container |

<!-- scanner-compatibility:end -->

The Nuclei template manifest is content addressed. It contains one reviewed,
passive pilot template. The default manager harness remains execution-disabled;
a separate worker-local policy is required before the private-lab pilot can run.
