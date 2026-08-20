import json
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/acceptance/V380_durable_installed_tools_acceptance_receipt.json"
URLS = Path("/tmp/vh-v380-app-owned-url-inventory.txt")
OUTPUT = ROOT / "docs/acceptance/assets/v380_component_transport_summary.png"

receipt = json.loads(RECEIPT.read_text())
components = [
    item
    for item in receipt["candidate_observations"]
    if item.get("weakness_id") == "android-exported-component"
]

app_owned = sum(item["component"].startswith("com.macrovideo.v380pro") for item in components)
sdk_owned = len(components) - app_owned
types = Counter(item["evidence"]["component_type"].title() for item in components)
urls = URLS.read_text().splitlines()
protocols = Counter("HTTP" if url.startswith("http://") else "HTTPS" for url in urls)

plt.style.use("default")
fig, axes = plt.subplots(1, 3, figsize=(16, 6.5), gridspec_kw={"width_ratios": [1.05, 1.1, 1.25]})
fig.patch.set_facecolor("#07111f")
for ax in axes:
    ax.set_facecolor("#0d1b2a")

colors = ["#f5a623", "#54c6e8"]
axes[0].pie(
    [app_owned, sdk_owned],
    labels=["App-owned\n8", "SDKs\n9"],
    colors=colors,
    startangle=90,
    wedgeprops={"width": 0.46, "edgecolor": "#0d1b2a", "linewidth": 4},
    textprops={"color": "#ecf3f8", "fontsize": 13, "weight": "bold"},
)
axes[0].text(0, 0.08, "17", color="#ffffff", ha="center", va="center", fontsize=36, weight="bold")
axes[0].text(
    0, -0.19, "exported components", color="#b7c6d1", ha="center", va="center", fontsize=11
)
axes[0].set_title("Ownership", color="#ffffff", fontsize=17, weight="bold", pad=20)

ordered_types = ["Activity", "Service", "Receiver", "Provider"]
values = [types[component_type] for component_type in ordered_types]
bars = axes[1].barh(
    ordered_types, values, color=["#f5a623", "#54c6e8", "#9b7bff", "#e8698d"], height=0.58
)
axes[1].invert_yaxis()
axes[1].set_xlim(0, max(values) + 2)
axes[1].set_xticks([])
axes[1].spines[:].set_visible(False)
axes[1].tick_params(axis="y", colors="#ecf3f8", labelsize=13)
for bar, value in zip(bars, values, strict=True):
    axes[1].text(
        value + 0.2,
        bar.get_y() + bar.get_height() / 2,
        str(value),
        color="#ffffff",
        va="center",
        fontsize=14,
        weight="bold",
    )
axes[1].set_title("Component types", color="#ffffff", fontsize=17, weight="bold", pad=20)

protocol_order = ["HTTP", "HTTPS"]
protocol_values = [protocols[protocol] for protocol in protocol_order]
bars = axes[2].bar(protocol_order, protocol_values, color=["#e85d75", "#4ccf9a"], width=0.55)
axes[2].set_ylim(0, max(protocol_values) + 14)
axes[2].set_yticks([])
axes[2].spines[:].set_visible(False)
axes[2].tick_params(axis="x", colors="#ecf3f8", labelsize=14)
for bar, value in zip(bars, protocol_values, strict=True):
    axes[2].text(
        bar.get_x() + bar.get_width() / 2,
        value + 1.3,
        str(value),
        color="#ffffff",
        ha="center",
        fontsize=18,
        weight="bold",
    )
axes[2].text(
    0.5,
    0.02,
    "de-duplicated app-owned URL string literals",
    transform=axes[2].transAxes,
    color="#b7c6d1",
    ha="center",
    fontsize=10,
)
axes[2].set_title("Protocol inventory", color="#ffffff", fontsize=17, weight="bold", pad=20)

fig.suptitle(
    "V380 Static Review: Component Exposure and Transport Indicators",
    color="#ffffff",
    fontsize=22,
    weight="bold",
    y=0.97,
)
fig.text(
    0.5,
    0.02,
    "Evidence: final durable-policy acceptance receipt and retained partial JADX source inventory. "
    "Static evidence only; no endpoint contact or APK execution.",
    color="#b7c6d1",
    ha="center",
    fontsize=10,
)
fig.subplots_adjust(top=0.82, bottom=0.12, left=0.06, right=0.98, wspace=0.35)
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(OUTPUT, dpi=180, facecolor=fig.get_facecolor(), bbox_inches="tight")
print(OUTPUT)
