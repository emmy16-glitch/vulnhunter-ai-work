"""Safe binary inspection that never executes the supplied artifact."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path

from .models import (
    BinaryAnalysisPolicy,
    BinaryArchitecture,
    BinaryArtifact,
    BinaryFormat,
    StaticSignal,
)

_PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")
_SUSPICIOUS_TOKENS: tuple[tuple[bytes, str, str], ...] = (
    (b"/bin/sh", "shell-reference", "high"),
    (b"cmd.exe", "command-shell-reference", "high"),
    (b"powershell", "powershell-reference", "high"),
    (b"CreateRemoteThread", "process-injection-api", "high"),
    (b"VirtualAllocEx", "remote-memory-api", "high"),
    (b"ptrace", "debug-or-injection-api", "medium"),
    (b"LD_PRELOAD", "loader-preload-reference", "medium"),
    (b"curl ", "network-download-command", "medium"),
    (b"wget ", "network-download-command", "medium"),
    (b"BEGIN PRIVATE KEY", "embedded-private-key-marker", "critical"),
)


class BinaryAnalysisError(RuntimeError):
    """Raised when an artifact cannot be inspected safely."""


class StaticBinaryAnalyzer:
    """Analyze immutable bytes inside an authorized root without execution."""

    def __init__(
        self, *, authorized_root: Path, policy: BinaryAnalysisPolicy | None = None
    ) -> None:
        self.root = authorized_root.resolve(strict=True)
        if not self.root.is_dir():
            raise BinaryAnalysisError("authorized binary root must be a directory")
        self.policy = policy or BinaryAnalysisPolicy()
        if self.policy.execute_artifact:
            raise BinaryAnalysisError("binary execution is prohibited by this analyzer")

    def analyze(self, candidate: Path) -> BinaryArtifact:
        path = candidate if candidate.is_absolute() else self.root / candidate
        if path.is_symlink() and not self.policy.permit_symlinks:
            raise BinaryAnalysisError("symbolic links are rejected")
        try:
            resolved = path.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise BinaryAnalysisError("binary artifact is unavailable") from exc
        if not resolved.is_relative_to(self.root):
            raise BinaryAnalysisError("binary artifact escapes the authorized root")
        if not resolved.is_file():
            raise BinaryAnalysisError("binary artifact must be a regular file")
        stat_before = resolved.stat()
        if stat_before.st_size > self.policy.maximum_bytes:
            raise BinaryAnalysisError("binary artifact exceeds the configured size limit")
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            raise BinaryAnalysisError("binary artifact could not be read safely") from exc
        stat_after = resolved.stat()
        if (stat_before.st_ino, stat_before.st_size, stat_before.st_mtime_ns) != (
            stat_after.st_ino,
            stat_after.st_size,
            stat_after.st_mtime_ns,
        ):
            raise BinaryAnalysisError("binary artifact changed during inspection")

        fmt, architecture = _identify(data)
        strings = _extract_strings(
            data,
            minimum_length=self.policy.minimum_string_length,
            maximum=self.policy.maximum_strings,
        )
        signals = _signals(data, entropy=_entropy(data))
        return BinaryArtifact(
            source_path=resolved.relative_to(self.root).as_posix(),
            filename=resolved.name,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            format=fmt,
            architecture=architecture,
            entropy=_entropy(data),
            printable_strings=strings,
            signals=signals,
            executed=False,
        )


def _identify(data: bytes) -> tuple[BinaryFormat, BinaryArchitecture]:
    if data.startswith(b"\x7fELF"):
        architecture = BinaryArchitecture.UNKNOWN
        if len(data) > 19:
            machine = int.from_bytes(data[18:20], "little")
            architecture = {
                3: BinaryArchitecture.X86,
                62: BinaryArchitecture.X86_64,
                40: BinaryArchitecture.ARM,
                183: BinaryArchitecture.ARM64,
            }.get(machine, BinaryArchitecture.UNKNOWN)
        return BinaryFormat.ELF, architecture
    if data.startswith(b"MZ"):
        return BinaryFormat.PE, BinaryArchitecture.UNKNOWN
    if data.startswith(
        (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    ):
        return BinaryFormat.MACH_O, BinaryArchitecture.UNKNOWN
    if data.startswith(b"PK\x03\x04"):
        return BinaryFormat.ZIP, BinaryArchitecture.UNKNOWN
    if data.startswith(b"dex\n"):
        return BinaryFormat.DEX, BinaryArchitecture.UNKNOWN
    return BinaryFormat.UNKNOWN, BinaryArchitecture.UNKNOWN


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 4)


def _extract_strings(data: bytes, *, minimum_length: int, maximum: int) -> tuple[str, ...]:
    if maximum == 0:
        return ()
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum_length)
    values: list[str] = []
    for match in pattern.finditer(data):
        text = match.group().decode("ascii", errors="replace")[:512]
        values.append(text)
        if len(values) >= maximum:
            break
    return tuple(values)


def _signals(data: bytes, *, entropy: float) -> tuple[StaticSignal, ...]:
    signals: list[StaticSignal] = []
    lowered = data.lower()
    for token, signal_id, severity in _SUSPICIOUS_TOKENS:
        if token.lower() in lowered:
            signals.append(
                StaticSignal(
                    signal_id=signal_id,
                    title=signal_id.replace("-", " ").title(),
                    severity=severity,
                    confidence="observed",
                    evidence=(f"literal:{token.decode('ascii', errors='replace')}",),
                )
            )
    if len(data) >= 1024 and entropy >= 7.2:
        signals.append(
            StaticSignal(
                signal_id="high-entropy-content",
                title="High Entropy Content",
                severity="medium",
                confidence="heuristic",
                evidence=(f"entropy:{entropy:.4f}",),
            )
        )
    return tuple(signals)
