from __future__ import annotations

from pathlib import Path

from scripts.mobile_network_inventory import inventory


def test_inventory_extracts_urls_hosts_and_network_context(tmp_path: Path) -> None:
    dex = tmp_path / "classes.dex"
    dex.write_bytes(
        b"https://api.av380.net/DeviceManage/V1/GetDeviceType\x00"
        b"mqtt://broker.av380.net:1883/device\x00"
        b"addJavascriptInterface setJavaScriptEnabled\x00"
    )

    result = inventory([dex])

    assert result["dex_count"] == 1
    assert "https://api.av380.net/DeviceManage/V1/GetDeviceType" in result["unique_urls"]
    assert "mqtt://broker.av380.net:1883/device" in result["unique_urls"]
    assert "api.av380.net" in result["unique_probable_hosts"]
    contexts = result["dex_results"][0]["network_context_strings"]
    assert any("addJavascriptInterface" in item["value"] for item in contexts)


def test_inventory_extracts_utf16le_urls(tmp_path: Path) -> None:
    dex = tmp_path / "classes2.dex"
    dex.write_bytes("https://mapi.av380.net/".encode("utf-16le") + b"\x00\x00")

    result = inventory([dex])

    assert "https://mapi.av380.net/" in result["unique_urls"]


def test_inventory_ignores_java_class_names_as_hosts(tmp_path: Path) -> None:
    dex = tmp_path / "classes3.dex"
    dex.write_bytes(
        b"Landroidx.compose.ui.window.ComposableSingletons;\x00"
        b"1.2.840.113549.1.1.11\x00"
        b"https://nvcam.net/\x00"
    )

    result = inventory([dex])

    assert "nvcam.net" in result["unique_probable_hosts"]
    assert not any("androidx.compose" in item for item in result["unique_probable_hosts"])
    assert not any(item.startswith("1.2.840") for item in result["unique_probable_hosts"])
