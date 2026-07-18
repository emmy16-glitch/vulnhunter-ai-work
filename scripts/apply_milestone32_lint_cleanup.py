from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"expected text is missing from {relative}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def remove_once(relative: str, block: str) -> None:
    replace_once(relative, block, "")


def main() -> None:
    replace_once(
        "vulnhunter/providers/groq.py",
        "                response_limit = maximum_bytes if response.is_success else min(maximum_bytes, 16_384)\n",
        "                response_limit = (\n"
        "                    maximum_bytes\n"
        "                    if response.is_success\n"
        "                    else min(maximum_bytes, 16_384)\n"
        "                )\n",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '    def from_path(cls, path: Path) -> "NucleiPilotPolicy":\n',
        "    def from_path(cls, path: Path) -> NucleiPilotPolicy:\n",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '                raise NucleiExecutionError("approved template is unavailable or escaped its root") from exc\n',
        "                raise NucleiExecutionError(\n"
        '                    "approved template is unavailable or escaped its root"\n'
        "                ) from exc\n",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '            raise NucleiExecutionError("the exact reviewed template selection could not be resolved")\n',
        "            raise NucleiExecutionError(\n"
        '                "the exact reviewed template selection could not be resolved"\n'
        "            )\n",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '            template_id = str(item.get("template-id") or item.get("template_id") or "nuclei-match")\n',
        "            template_id = str(\n"
        '                item.get("template-id") or item.get("template_id") or "nuclei-match"\n'
        "            )\n",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        '            matched = str(item.get("matched-at") or item.get("matched_at") or item.get("host") or "")\n',
        "            matched = str(\n"
        '                item.get("matched-at")\n'
        '                or item.get("matched_at")\n'
        '                or item.get("host")\n'
        '                or ""\n'
        "            )\n",
    )
    replace_once(
        "vulnhunter/security_tools/nuclei_worker_pilot.py",
        "        if current.state is ScannerJobState.CANCELLING and target_state is not ScannerJobState.CANCELLED:\n",
        "        if (\n"
        "            current.state is ScannerJobState.CANCELLING\n"
        "            and target_state is not ScannerJobState.CANCELLED\n"
        "        ):\n",
    )
    replace_once(
        "vulnhunter/security_tools/verification_pipeline.py",
        "    def _artifact_context(self, result: ScannerAdapterResult) -> tuple[Path | None, tuple[str, ...]]:\n",
        "    def _artifact_context(\n"
        "        self, result: ScannerAdapterResult\n"
        "    ) -> tuple[Path | None, tuple[str, ...]]:\n",
    )
    for line in (
        '    os.environ.setdefault("VULNHUNTER_OLLAMA_ENDPOINT", "http://127.0.0.1:11434")\n',
        '    os.environ.setdefault("VULNHUNTER_OLLAMA_CONTEXT_TOKENS", "1024")\n',
        '    os.environ.setdefault("VULNHUNTER_OLLAMA_TIMEOUT_SECONDS", "600")\n',
    ):
        remove_once("scripts/run_local_preview.py", line)
    remove_once(
        "vulnhunter/security_tools/catalog.py",
        '''        SecurityToolDefinition(
            tool_id="greenbone",
            display_name="Greenbone Community Edition",
            executable_candidates=("gvm-cli", "greenbone-nvt-sync"),
            profiles=(ToolProfile.ACTIVE_ASSESSMENT, ToolProfile.RETEST),
            target_kinds=network,
            action_class=ActionClass.SENSITIVE,
            approval_required=True,
            connector_only=True,
            output_formats=("xml",),
            description="Broad vulnerability-management and assessment connector.",
        ),
''',
    )


if __name__ == "__main__":
    main()
