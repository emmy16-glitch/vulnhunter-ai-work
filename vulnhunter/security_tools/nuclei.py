"""Governed Nuclei command policy and JSONL normalization.

This module intentionally exposes a narrow, fixed policy surface. It does not
accept raw command-line arguments, template URLs, cloud upload, public OAST,
AI-generated templates, local-file access, code templates, file templates,
self-contained templates, DAST server mode, or discovery-engine queries.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from vulnhunter.actions.models import sha256_json
from vulnhunter.security_tools.models import (
    SecurityToolRequest,
    ToolProfile,
)
from vulnhunter.security_tools.parsers import NormalizedFinding

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
_ALLOWED_STANDARD_TYPES = {"http", "ssl", "dns", "tcp", "websocket", "whois"}
_ALLOWED_INTRUSIVE_TYPES = _ALLOWED_STANDARD_TYPES | {"headless", "javascript"}
_SAFE_PASSIVE_TAGS = {"tech", "exposure", "misconfig", "ssl", "dns"}
_REDACT_KEYS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "token",
    "password",
    "secret",
)


class NucleiPolicyError(ValueError):
    """Raised when a Nuclei request violates the fixed VulnHunter policy."""


@dataclass(frozen=True)
class NucleiCommand:
    """A fixed Nuclei command plus execution-isolation requirements."""

    argv: tuple[str, ...]
    requires_isolation: bool


def _string_list(
    parameters: dict[str, object],
    key: str,
    *,
    default: tuple[str, ...] = (),
) -> tuple[str, ...]:
    value = parameters.get(key, default)
    if isinstance(value, str):
        items = tuple(part.strip() for part in value.split(",") if part.strip())
    elif isinstance(value, (list, tuple)):
        items = tuple(str(part).strip() for part in value if str(part).strip())
    else:
        raise NucleiPolicyError(f"nuclei {key} must be a string or list of strings")

    if len(items) > 128:
        raise NucleiPolicyError(f"nuclei {key} exceeds the maximum item count")
    if any(_SAFE_TOKEN.fullmatch(item) is None for item in items):
        raise NucleiPolicyError(f"nuclei {key} contains an unsupported value")
    return tuple(dict.fromkeys(items))


def _bounded_int(
    parameters: dict[str, object],
    key: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    value = parameters.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise NucleiPolicyError(f"nuclei {key} must be an integer")
    if value < minimum or value > maximum:
        raise NucleiPolicyError(f"nuclei {key} must be between {minimum} and {maximum}")
    return value


def _require_true(parameters: dict[str, object], key: str, message: str) -> None:
    if parameters.get(key) is not True:
        raise NucleiPolicyError(message)


def _reject_unsafe_parameters(parameters: dict[str, object]) -> None:
    blocked = {
        "raw_args",
        "template_urls",
        "workflow_urls",
        "ai_prompt",
        "prompt",
        "cloud_upload",
        "dashboard",
        "dashboard_upload",
        "public_oast",
        "interactsh_server",
        "interactsh_token",
        "allow_local_file_access",
        "code_templates",
        "file_templates",
        "self_contained_templates",
        "dast",
        "dast_server",
        "uncover",
        "secret_file",
        "headers",
        "proxy",
    }
    attempted = sorted(key for key in blocked if key in parameters)
    if attempted:
        raise NucleiPolicyError(
            "nuclei request contains blocked parameters: " + ", ".join(attempted)
        )


def build_nuclei_command(
    request: SecurityToolRequest,
    *,
    executable: str,
    output: Path,
) -> NucleiCommand:
    """Build a low-resource, cloud-free, signed-template Nuclei command."""

    parameters = request.parameters
    _reject_unsafe_parameters(parameters)

    scan_profile = str(parameters.get("scan_profile", "passive")).strip().lower()
    if scan_profile not in {"passive", "standard", "intrusive", "retest"}:
        raise NucleiPolicyError("nuclei scan_profile is unsupported")

    allowed_profiles = {
        "passive": {ToolProfile.SAFE_ASSESSMENT},
        "standard": {ToolProfile.SAFE_ASSESSMENT, ToolProfile.ACTIVE_ASSESSMENT},
        "intrusive": {ToolProfile.ACTIVE_ASSESSMENT, ToolProfile.VALIDATION},
        "retest": {ToolProfile.RETEST},
    }
    if request.profile not in allowed_profiles[scan_profile]:
        raise NucleiPolicyError(
            f"nuclei {scan_profile} profile is incompatible with {request.profile.value}"
        )

    template_ids = _string_list(parameters, "template_ids")
    tags = _string_list(parameters, "tags")
    severities = _string_list(
        parameters,
        "severity",
        default=("info", "low", "medium", "high", "critical"),
    )
    if not severities or any(value not in _ALLOWED_SEVERITIES for value in severities):
        raise NucleiPolicyError("nuclei severity contains an unsupported value")

    if scan_profile == "passive":
        if template_ids:
            raise NucleiPolicyError(
                "nuclei passive profile uses reviewed safe tags, not template IDs"
            )
        tags = tags or ("tech", "exposure", "misconfig")
        if any(tag not in _SAFE_PASSIVE_TAGS for tag in tags):
            raise NucleiPolicyError("nuclei passive tags are outside the safe baseline")
        protocol_types = ("http", "ssl", "dns")
    else:
        if not template_ids and not tags:
            raise NucleiPolicyError(
                f"nuclei {scan_profile} profile requires explicit template IDs or tags"
            )
        requested_types = set(
            _string_list(
                parameters,
                "protocol_types",
                default=("http", "ssl", "dns", "tcp"),
            )
        )
        allowed_types = (
            _ALLOWED_INTRUSIVE_TYPES if scan_profile == "intrusive" else _ALLOWED_STANDARD_TYPES
        )
        if not requested_types or not requested_types <= allowed_types:
            raise NucleiPolicyError("nuclei protocol_types contain an unsupported type")
        protocol_types = tuple(sorted(requested_types))

    requires_isolation = scan_profile == "intrusive"
    if scan_profile == "intrusive":
        _require_true(
            parameters,
            "intrusive_approved",
            "nuclei intrusive profile requires exact human approval",
        )
        if not template_ids:
            raise NucleiPolicyError(
                "nuclei intrusive profile requires explicit approved template IDs"
            )

    if scan_profile == "retest" and not template_ids:
        raise NucleiPolicyError("nuclei retest profile requires exact approved template IDs")

    private_network_approved = parameters.get("private_network_approved", False)
    if not isinstance(private_network_approved, bool):
        raise NucleiPolicyError("nuclei private_network_approved must be boolean")
    if private_network_approved and request.profile not in {
        ToolProfile.ACTIVE_ASSESSMENT,
        ToolProfile.VALIDATION,
        ToolProfile.RETEST,
    }:
        raise NucleiPolicyError(
            "nuclei private-network access requires active, validation, or retest profile"
        )

    rate_limit = _bounded_int(parameters, "rate_limit", default=5, minimum=1, maximum=10)
    bulk_size = _bounded_int(parameters, "bulk_size", default=2, minimum=1, maximum=2)
    concurrency = _bounded_int(parameters, "concurrency", default=2, minimum=1, maximum=2)
    probe_concurrency = _bounded_int(
        parameters, "probe_concurrency", default=2, minimum=1, maximum=2
    )
    request_timeout = _bounded_int(parameters, "request_timeout", default=10, minimum=1, maximum=30)
    retries = _bounded_int(parameters, "retries", default=1, minimum=0, maximum=1)

    argv: list[str] = [
        executable,
        "-u",
        request.target,
        "-jsonl-export",
        str(output),
        "-silent",
        "-no-color",
        "-timestamp",
        "-disable-unsigned-templates",
        "-disable-update-check",
        "-no-stdin",
        "-omit-template",
        "-no-interactsh",
        "-redact",
        ",".join(_REDACT_KEYS),
        "-severity",
        ",".join(severities),
        "-type",
        ",".join(protocol_types),
        "-rate-limit",
        str(rate_limit),
        "-bulk-size",
        str(bulk_size),
        "-concurrency",
        str(concurrency),
        "-probe-concurrency",
        str(probe_concurrency),
        "-payload-concurrency",
        "1",
        "-timeout",
        str(request_timeout),
        "-retries",
        str(retries),
        "-max-host-error",
        "10",
    ]

    if not private_network_approved:
        argv.append("-restrict-local-network-access")
    if tags:
        argv.extend(("-tags", ",".join(tags)))
    if template_ids:
        argv.extend(("-template-id", ",".join(template_ids)))
    if "headless" in protocol_types:
        argv.extend(
            (
                "-headless",
                "-headless-concurrency",
                "1",
                "-headless-bulk-size",
                "1",
            )
        )
    if "javascript" in protocol_types:
        argv.extend(("-js-concurrency", "1"))

    return NucleiCommand(
        argv=tuple(argv),
        requires_isolation=requires_isolation,
    )


def _safe_url_reference(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    split = urlsplit(value)
    if split.scheme and split.netloc:
        host = split.hostname or split.netloc
        path = split.path or "/"
        return f"{split.scheme}://{host}{path}"
    return value[:500]


def parse_nuclei_jsonl(
    path: Path,
    *,
    target_reference: str,
) -> tuple[NormalizedFinding, ...]:
    """Normalize Nuclei JSONL without copying raw request/response data."""

    data = path.read_bytes()
    source_digest = hashlib.sha256(data).hexdigest()
    findings: list[NormalizedFinding] = []

    for index, line in enumerate(
        data.decode("utf-8", errors="replace").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue

        info = item.get("info")
        info = info if isinstance(info, dict) else {}
        classification = info.get("classification")
        classification = classification if isinstance(classification, dict) else {}

        template_id = str(
            item.get("template-id")
            or item.get("templateID")
            or item.get("template_id")
            or "unknown-template"
        )
        matched_at = _safe_url_reference(
            item.get("matched-at") or item.get("matched") or item.get("host") or target_reference
        )
        title = str(info.get("name") or item.get("name") or template_id)
        severity = str(info.get("severity") or item.get("severity") or "unknown").lower()
        record_digest = sha256_json(item)

        tags = info.get("tags")
        if isinstance(tags, str):
            safe_tags: object = tuple(part.strip() for part in tags.split(",") if part.strip())
        elif isinstance(tags, list):
            safe_tags = tuple(str(part)[:100] for part in tags[:50])
        else:
            safe_tags = ()

        evidence = {
            "record_index": index,
            "record_sha256": record_digest,
            "template_id": template_id,
            "template_path": str(item.get("template") or "")[:500] or None,
            "template_url": _safe_url_reference(item.get("template-url")),
            "matched_at": matched_at,
            "host": _safe_url_reference(item.get("host")),
            "ip": str(item.get("ip") or "")[:100] or None,
            "port": str(item.get("port") or "")[:20] or None,
            "protocol": str(item.get("type") or item.get("protocol") or "")[:50] or None,
            "matcher_name": str(item.get("matcher-name") or "")[:200] or None,
            "extractor_name": str(item.get("extractor-name") or "")[:200] or None,
            "timestamp": str(item.get("timestamp") or "")[:100] or None,
            "tags": safe_tags,
            "cve_id": classification.get("cve-id"),
            "cwe_id": classification.get("cwe-id"),
            "cvss_score": classification.get("cvss-score"),
        }

        findings.append(
            NormalizedFinding(
                finding_id=sha256_json(
                    {
                        "tool_id": "nuclei",
                        "template_id": template_id,
                        "matched_at": matched_at,
                        "source": source_digest,
                    }
                )[:24],
                tool_id="nuclei",
                title=title,
                severity=severity,
                target_reference=target_reference,
                evidence=evidence,
                confidence="candidate",
                source_sha256=source_digest,
            )
        )

    return tuple(findings)
