#!/usr/bin/env python3
"""Emit bounded JSON evidence from Androguard for one already-ingested APK.

This adapter is intentionally non-interactive. It does not install or execute the
application, make network requests, or write decompiled source code. The parent
worker applies process and output limits and treats this JSON as evidence rather
than a confirmed vulnerability report.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from androguard.core.apk import APK
from androguard.core.dex import DEX

_DANGEROUS_PERMISSIONS = {
    "android.permission.ACCEPT_HANDOVER",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.USE_SIP",
    "android.permission.UWB_RANGING",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}

_API_FAMILIES = {
    "webview": ("Landroid/webkit/WebView;", "Landroid/webkit/WebSettings;"),
    "cryptography": ("Ljavax/crypto/", "Ljava/security/", "Landroid/security/keystore/"),
    "network": ("Ljava/net/", "Lokhttp3/", "Lorg/apache/http/"),
    "database": ("Landroid/database/sqlite/", "Landroidx/room/"),
    "ipc": ("Landroid/content/Intent;", "Landroid/os/Binder;", "Landroid/app/PendingIntent;"),
    "native_loading": ("Ljava/lang/System;", "Ljava/lang/Runtime;"),
}


def _safe_call(target: object, name: str, default: object) -> object:
    method = getattr(target, name, None)
    if method is None:
        return default
    try:
        value = method()
    except Exception:
        return default
    return default if value is None else value


def _strings(values: object, *, maximum: int = 2_000) -> list[str]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    return sorted({str(value) for value in values if str(value).strip()})[:maximum]


def _api_family_counts(analysis: object, *, maximum_methods: int = 250_000) -> dict[str, int]:
    counters: Counter[str] = Counter()
    getter = getattr(analysis, "get_methods", None)
    if getter is None:
        return {family: 0 for family in _API_FAMILIES}
    try:
        methods = getter()
    except Exception:
        return {family: 0 for family in _API_FAMILIES}
    for index, method_analysis in enumerate(methods):
        if index >= maximum_methods:
            break
        method = getattr(method_analysis, "method", method_analysis)
        class_name = str(getattr(method, "class_name", ""))
        descriptor = str(getattr(method, "descriptor", ""))
        combined = f"{class_name}{descriptor}"
        for family, needles in _API_FAMILIES.items():
            if any(needle in combined for needle in needles):
                counters[family] += 1
    return {family: int(counters[family]) for family in _API_FAMILIES}


def analyze(apk_path: Path) -> dict[str, object]:
    # AnalyzeAPK eagerly builds a whole-program cross-reference graph. That
    # graph is unnecessary for this adapter’s bounded manifest and inventory
    # evidence and exceeds memory on large multi-DEX APKs such as V380. Parse
    # the APK and each DEX independently so the worker can remain read-only and
    # fail closed without losing the deterministic metadata surface.
    apk = APK(str(apk_path), skip_analysis=False)
    dex_files = [DEX(buff) for buff in apk.get_all_dex()]
    permissions = _strings(_safe_call(apk, "get_permissions", []))
    dangerous = sorted(
        permission for permission in permissions if permission in _DANGEROUS_PERMISSIONS
    )
    class_count = 0
    for dex in dex_files or []:
        classes = _safe_call(dex, "get_classes", [])
        if isinstance(classes, (list, tuple, set, frozenset)):
            class_count += len(classes)

    return {
        "schema_version": "1.0",
        "package_name": str(_safe_call(apk, "get_package", "")),
        "app_name": str(_safe_call(apk, "get_app_name", "")),
        "version_code": str(_safe_call(apk, "get_androidversion_code", "")),
        "version_name": str(_safe_call(apk, "get_androidversion_name", "")),
        "min_sdk": str(_safe_call(apk, "get_min_sdk_version", "")),
        "target_sdk": str(_safe_call(apk, "get_target_sdk_version", "")),
        "permissions": permissions,
        "dangerous_permissions": dangerous,
        "activities": _strings(_safe_call(apk, "get_activities", [])),
        "services": _strings(_safe_call(apk, "get_services", [])),
        "receivers": _strings(_safe_call(apk, "get_receivers", [])),
        "providers": _strings(_safe_call(apk, "get_providers", [])),
        "dex_count": len(dex_files or []),
        "class_count": class_count,
        "api_family_counts": {
            family: sum(_api_family_counts(dex).get(family, 0) for dex in dex_files)
            for family in _API_FAMILIES
        },
    }


def _quiet_androguard_logging() -> None:
    try:
        from loguru import logger
    except ImportError:
        return
    logger.remove()
    logger.add(sys.stderr, level="ERROR")


def main() -> int:
    _quiet_androguard_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    args = parser.parse_args()
    apk_path = args.apk.expanduser().resolve(strict=True)
    if not apk_path.is_file():
        raise SystemExit("APK path is not a regular file")
    print(json.dumps(analyze(apk_path), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
