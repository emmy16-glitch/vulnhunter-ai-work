"""Extract URL and network-communication indicators from extracted DEX files.

This utility is intentionally read-only and offline. It scans printable ASCII and
UTF-16LE strings from DEX bytecode/data and reports indicators as evidence, not as
proof that a host is contacted at runtime.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_ASCII_STRING = re.compile(rb"[ -~]{4,}")
_UTF16LE_STRING = re.compile(rb"(?:[ -~]\x00){4,}")
_URL = re.compile(r"(?i)\b(?:https?|wss?|mqtt|rtsp|rtmp|tcp|udp)://[^\s\"'<>\\]+")
_HOST = re.compile(
    r"(?i)(?<![a-z0-9-])(?=[a-z0-9.-]{3,253}(?::\d{1,5})?(?:/[^\s\"'<>\\]*)?$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})"
    r"(?::\d{1,5})?(?:/[^\s\"'<>\\]*)?"
)
_KNOWN_TLDS = {
    "ai",
    "app",
    "biz",
    "ca",
    "cc",
    "cn",
    "cloud",
    "co",
    "com",
    "de",
    "dev",
    "eu",
    "fr",
    "in",
    "info",
    "io",
    "jp",
    "kr",
    "live",
    "me",
    "net",
    "online",
    "org",
    "pro",
    "ru",
    "sa",
    "shop",
    "site",
    "sg",
    "tech",
    "top",
    "tv",
    "uk",
    "us",
    "xyz",
}

_NETWORK_CONTEXT = re.compile(
    r"(?i)(?:\b(?:api|baseurl|endpoint|host|server|socket|websocket|mqtt|tcp|udp|"
    r"okhttp|retrofit|volley|grpc|dns|proxy|tls|ssl|certificate|pinning|download|"
    r"upload|cloud|lan|device|stream|rtsp|rtmp|xmpp|push|firebase|jpush|webview|"
    r"javascript|loadurl|evaluatejavascript|addjavascriptinterface|"
    r"setjavascriptenabled)\b|(?:https?|wss?|mqtt|rtsp|rtmp|tcp|udp)://)"
)


def _clean(value: str) -> str:
    value = value.strip()
    edge = "\\\\\\\"'`,;()[]{}<>"
    while value and value[0] in edge:
        value = value[1:]
    while value and value[-1] in edge + ".,;":
        value = value[:-1]
    return value


def _strings(data: bytes) -> list[tuple[int, str, str]]:
    values: list[tuple[int, str, str]] = []
    for match in _ASCII_STRING.finditer(data):
        values.append((match.start(), match.group().decode("utf-8", "replace"), "ascii"))
    for match in _UTF16LE_STRING.finditer(data):
        values.append((match.start(), match.group()[::2].decode("utf-8", "replace"), "utf16le"))
    return sorted(values, key=lambda item: (item[0], item[2]))


def _host_is_probable(value: str) -> bool:
    if _HOST.fullmatch(value) is None:
        return False
    authority = value.split("/", 1)[0].split(":", 1)[0]
    labels = authority.split(".")
    if all(label.isdigit() for label in labels):
        return False
    if labels[-1].lower().removeprefix("xn--") not in _KNOWN_TLDS:
        return False
    if any(label[:1].isupper() for label in labels):
        return False
    return True


def inventory(dex_paths: list[Path]) -> dict[str, object]:
    dex_results: list[dict[str, object]] = []
    for path in sorted(dex_paths):
        data = path.read_bytes()
        urls: set[str] = set()
        hosts: set[str] = set()
        contexts: list[dict[str, object]] = []
        seen_contexts: set[tuple[int, str, str]] = set()
        for offset, value, encoding in _strings(data):
            url_values = {_clean(item) for item in _URL.findall(value)}
            host_values = {
                _clean(item) for item in _HOST.findall(value) if _host_is_probable(_clean(item))
            }
            urls.update(item for item in url_values if item)
            hosts.update(item.split("/", 1)[0] for item in host_values if item)
            if _NETWORK_CONTEXT.search(value):
                key = (offset, encoding, value)
                if key not in seen_contexts:
                    seen_contexts.add(key)
                    contexts.append(
                        {
                            "offset": offset,
                            "encoding": encoding,
                            "value": value,
                        }
                    )
        dex_results.append(
            {
                "dex": path.name,
                "path": str(path),
                "size_bytes": len(data),
                "urls": sorted(urls),
                "probable_hosts": sorted(hosts),
                "network_context_strings": contexts,
            }
        )
    return {
        "schema_version": "1.0",
        "dex_count": len(dex_results),
        "unique_urls": sorted({item for result in dex_results for item in result["urls"]}),
        "unique_probable_hosts": sorted(
            {item for result in dex_results for item in result["probable_hosts"]}
        ),
        "dex_results": dex_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dex", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    paths = [path.expanduser().resolve(strict=True) for path in args.dex]
    if any(not path.is_file() or path.suffix != ".dex" for path in paths):
        raise SystemExit("all --dex paths must be regular .dex files")
    payload = inventory(paths)
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        destination = args.output.expanduser().absolute()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
