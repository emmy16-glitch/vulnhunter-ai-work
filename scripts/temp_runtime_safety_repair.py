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


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    changed = repair_runtime(root / "vulnhunter/mobile/runtime.py")
    print(f"runtime safety files changed: {int(changed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
