from vulnhunter.mobile import analyze_decoded_manifest, correlate_mobile_findings
from vulnhunter.mobile.models import MobileFinding

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="example.mobile">
  <uses-permission android:name="android.permission.CAMERA" />
  <application
      android:debuggable="true"
      android:allowBackup="true"
      android:usesCleartextTraffic="true">
    <activity android:name=".ExportedActivity" android:exported="true" />
  </application>
</manifest>
"""


def test_manifest_analyzer_returns_candidate_security_observations(tmp_path):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(MANIFEST)

    findings = analyze_decoded_manifest(manifest, artifact_sha256="a" * 64)
    weaknesses = {item.weakness_id for item in findings}

    assert "android-debuggable-enabled" in weaknesses
    assert "android-cleartext-traffic" in weaknesses
    assert "android-backup-enabled" in weaknesses
    assert "android-exported-component" in weaknesses
    assert all(item.confidence == "candidate" for item in findings)


def test_mobile_finding_correlation_combines_tool_evidence():
    first = MobileFinding(
        finding_id="finding-source-01",
        weakness_id="android-cleartext-traffic",
        title="Cleartext traffic is permitted",
        severity="medium",
        component="application",
        tool_ids=("apktool-manifest",),
        artifact_sha256="b" * 64,
    )
    second = first.model_copy(
        update={
            "finding_id": "finding-source-02",
            "severity": "high",
            "tool_ids": ("mobsf",),
        }
    )

    correlated = correlate_mobile_findings((first, second))

    assert len(correlated) == 1
    assert correlated[0].severity == "high"
    assert correlated[0].confidence == "observed"
    assert correlated[0].tool_ids == ("apktool-manifest", "mobsf")
