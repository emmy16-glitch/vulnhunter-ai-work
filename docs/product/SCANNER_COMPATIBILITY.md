# Scanner Compatibility

The authoritative machine-readable record is
`config/security_tools/scanner_compatibility.json`. Missing versions are
intentional blockers, not requests to install the latest release.

<!-- scanner-compatibility:start -->

| Scanner | Adapter | Adapter version | Engine | Feed | Status | Deployment |
|---|---|---:|---:|---:|---|---|
| mobile_analysis | mobile-analysis-planned-adapter | 0.1.0 | not selected | not selected | planned | disabled |
| nuclei | nuclei-controlled-harness | 1.2.0 | v3.8.0 | v10.4.5 | pilot_ready | isolated_container |

<!-- scanner-compatibility:end -->

The Nuclei descriptor means that a verified worker can process one approved,
signed passive job for one literal RFC1918 target. It does not authorize public
scanning or advertise intrusive, headless, JavaScript, code or file-template
support.

Run `python scripts/validate_scanner_compatibility.py` after changing an adapter,
engine pin, feed release or manifest digest.
