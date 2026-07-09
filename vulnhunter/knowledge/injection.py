"""Non-executing prompt-injection screening for untrusted source text."""

from __future__ import annotations

import re
from pathlib import Path

from vulnhunter.knowledge.models import InjectionFinding
from vulnhunter.security import redact_text

_TEXT_SUFFIXES = frozenset(
    {
        ".txt",
        ".md",
        ".markdown",
        ".csv",
        ".json",
        ".jsonl",
        ".yaml",
        ".yml",
        ".xml",
        ".html",
        ".htm",
        ".rst",
        ".log",
    }
)

_MAX_SCREEN_BYTES = 2 * 1024 * 1024

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore-prior-instructions",
        re.compile(
            r"\b(?:ignore|disregard|forget)\b.{0,80}\b(?:previous|prior|above|system)\b.{0,40}\b(?:instructions?|rules?|prompt)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system-prompt-request",
        re.compile(
            r"\b(?:reveal|show|print|return|repeat)\b.{0,60}\b"
            r"(?:system prompt|hidden prompt|developer message|internal instructions)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "command-execution-request",
        re.compile(
            r"\b(?:execute|run|launch|open a shell|use terminal|invoke)\b.{0,80}\b"
            r"(?:command|script|payload|binary|powershell|bash|terminal)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "secret-exfiltration-request",
        re.compile(
            r"\b(?:reveal|extract|send|upload|exfiltrate|print)\b.{0,80}\b"
            r"(?:secret|token|password|credential|cookie|private key|api key)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "code-modification-request",
        re.compile(
            r"\b(?:modify|overwrite|patch|delete|replace)\b.{0,80}\b"
            r"(?:source code|repository|file|configuration|database)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "scan-initiation-request",
        re.compile(
            r"\b(?:scan|attack|exploit|probe|brute[- ]?force)\b.{0,80}\b"
            r"(?:target|host|website|server|network|endpoint)\b",
            re.IGNORECASE,
        ),
    ),
)


def can_screen_source(path: Path) -> bool:
    """Return whether the source has a supported text format."""
    return path.suffix.lower() in _TEXT_SUFFIXES


def screen_source(path: Path) -> tuple[InjectionFinding, ...]:
    """Screen supported text files without interpreting or executing content."""
    if not can_screen_source(path):
        return ()

    with path.open("rb") as handle:
        data = handle.read(_MAX_SCREEN_BYTES + 1)

    if len(data) > _MAX_SCREEN_BYTES:
        data = data[:_MAX_SCREEN_BYTES]

    text = data.decode("utf-8", errors="replace")
    findings: list[InjectionFinding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern_id, pattern in _PATTERNS:
            if pattern.search(line):
                excerpt = redact_text(" ".join(line.strip().split()))[:240]
                findings.append(
                    InjectionFinding(
                        pattern_id=pattern_id,
                        line_number=line_number,
                        excerpt=excerpt or "[blank line]",
                    )
                )

    return tuple(findings)
