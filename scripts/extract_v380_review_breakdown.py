import json
import re
from pathlib import Path

receipt_path = Path("docs/acceptance/V380_durable_installed_tools_acceptance_receipt.json")
indicator_path = Path("/tmp/vh-v380-app-owned-indicators.txt")
receipt = json.loads(receipt_path.read_text())

exported = [
    item
    for item in receipt["candidate_observations"]
    if item.get("weakness_id") == "android-exported-component"
]
print("EXPORTED_COMPONENTS")
for item in exported:
    evidence = item.get("evidence", {})
    print(
        "\t".join(
            [
                item.get("component", ""),
                evidence.get("component_type", ""),
                item.get("severity", ""),
                item.get("status", ""),
                item.get("observation_id", ""),
            ]
        )
    )
print(f"COUNT\\t{len(exported)}")

print("CLEARTEXT_FINDINGS")
for item in receipt["candidate_observations"]:
    if item.get("weakness_id") == "android-cleartext-traffic":
        print(json.dumps(item, sort_keys=True))

print("APP_OWNED_HTTP_ENDPOINTS")
seen = set()
if indicator_path.exists():
    for line in indicator_path.read_text(errors="replace").splitlines():
        if "/com/macrovideo/v380pro/" not in line:
            continue
        urls = re.findall(r"https?://[^\" ]+", line)
        for url in urls:
            url = url.rstrip(";),")
            if url not in seen:
                seen.add(url)
                print(url)
print(f"COUNT\\t{len(seen)}")

print("RECEIPT_SUMMARY")
print(
    json.dumps(
        {
            "job_id": receipt.get("job_id"),
            "state": receipt.get("state"),
            "artifact_id": receipt.get("artifact_id"),
            "captures": len(receipt.get("captures", [])),
            "candidate_observations": len(receipt.get("candidate_observations", [])),
            "result_sha256": receipt.get("result_sha256"),
        },
        sort_keys=True,
    )
)
