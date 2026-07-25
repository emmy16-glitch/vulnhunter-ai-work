from __future__ import annotations

from pathlib import Path


def repair_runtime(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    guard = "runtime cleanup could not remove the approved package"
    if guard in text:
        return False
    lines = text.splitlines()
    matches = [
        index
        for index, line in enumerate(lines)
        if line.strip() == "captures.extend(self._cleanup(package_name))"
    ]
    if len(matches) != 1:
        raise RuntimeError("runtime cleanup call did not match exactly once")
    call_index = matches[0]
    if (
        call_index < 2
        or lines[call_index - 2].strip() != "finally:"
        or lines[call_index - 1].strip() != "if installed:"
    ):
        raise RuntimeError("runtime cleanup call is outside the expected finally block")
    replacement = [
        "        finally:",
        "            if installed:",
        "                try:",
        "                    cleanup = self._cleanup(package_name)",
        "                except (OSError, subprocess.SubprocessError, MobileRuntimeError) as exc:",
        "                    if failure is None:",
        "                        failure = exc",
        "                else:",
        "                    captures.extend(cleanup)",
        "                    if failure is None and any(",
        "                        item.return_code != 0 for item in cleanup",
        "                    ):",
        "                        failure = MobileRuntimeError(",
        f'                            "{guard}"',
        "                        )",
    ]
    lines[call_index - 2 : call_index + 1] = replacement
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def repair_spool(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    guard = "malformed_identity = canonical_job_id is None"
    if guard in text:
        return False
    start_marker = "    def reject(self, claimed: Path, *, reason: str, now: datetime) -> Path:\n"
    end_marker = "    def recover_processing(self, *, now: datetime) -> None:\n"
    start = text.find(start_marker)
    end = text.find(end_marker)
    if start < 0 or end <= start:
        raise RuntimeError("extension reject function boundaries were not found")
    replacement = '''    def reject(self, claimed: Path, *, reason: str, now: datetime) -> Path:
        if claimed.parent != self.processing or claimed.is_symlink() or not claimed.is_file():
            raise MobileExtensionSpoolError("claimed extension job path is unsafe")
        try:
            raw_text = claimed.read_text(encoding="utf-8")
            raw = json.loads(raw_text)
        except (OSError, ValueError):
            raw_text = ""
            raw = {}
        if not isinstance(raw, dict):
            raw = {}
        raw_job_id = str(raw.get("job_id") or "")
        canonical_job_id = (
            raw_job_id
            if _IDENTIFIER.fullmatch(raw_job_id) is not None
            and claimed.name == self._filename(raw_job_id)
            else None
        )
        malformed_identity = canonical_job_id is None
        instant = _utc(now)
        if malformed_identity:
            seed = f"{claimed.name}\\0{raw_text}\\0{instant.isoformat()}".encode("utf-8")
            job_id = f"rejected-{hashlib.sha256(seed).hexdigest()[:20]}"
        else:
            job_id = canonical_job_id
        raw_kind = str(raw.get("kind") or "mobsf")
        kind: ExtensionKind = "runtime" if raw_kind == "runtime" else "mobsf"
        raw_artifact_id = str(raw.get("artifact_id") or "")
        artifact_id = (
            raw_artifact_id
            if _IDENTIFIER.fullmatch(raw_artifact_id) is not None
            else "unknown-artifact"
        )
        safe_reason = " ".join(reason.split())[:500]
        if len(safe_reason) < 3:
            safe_reason = "Malformed extension job rejected."
        unsigned = {
            "job_id": job_id,
            "kind": kind,
            "artifact_id": artifact_id,
            "state": "rejected",
            "completed_at": instant.isoformat(),
            "reason": safe_reason,
            "evidence": {},
        }
        receipt = MobileExtensionReceipt(
            **unsigned,
            result_sha256=hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )
        if malformed_identity:
            target = self.failed / self._filename(job_id)
            self._write_exclusive(target, receipt.model_dump_json(indent=2) + "\\n")
            claimed.unlink(missing_ok=True)
            return target
        return self.finish(claimed, receipt=receipt, success=False)

'''
    path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
    return True


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    changed = [
        repair_runtime(root / "vulnhunter/mobile/runtime.py"),
        repair_spool(root / "vulnhunter/mobile/extension_spool.py"),
    ]
    print(f"runtime safety files changed: {sum(changed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
