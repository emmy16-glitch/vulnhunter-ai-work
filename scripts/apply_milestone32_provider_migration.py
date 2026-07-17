from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"expected block is missing from {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_services() -> None:
    path = ROOT / "vulnhunter/web/services.py"
    replace_once(
        path,
        """from vulnhunter.providers import (\n    GroqProvider,\n    GroqProviderError,\n    OllamaProvider,\n    OllamaProviderError,\n)\n""",
        "from vulnhunter.providers import GroqProvider, GroqProviderError\n",
    )
    text = path.read_text(encoding="utf-8")
    marker = "def intelligence_status() -> tuple[dict[str, str], ...]:\n"
    prefix, separator, _tail = text.partition(marker)
    if not separator:
        raise RuntimeError("intelligence_status marker is missing")
    replacement = '''def intelligence_status() -> tuple[dict[str, str], ...]:
    """Return non-secret graph, advisory, and verification states without inference."""

    repository_root = Path(settings.BASE_DIR).resolve()
    try:
        graphify = GraphifyAdapter(
            repository_roots=(repository_root,),
            output_root=Path(settings.VULNHUNTER_GRAPHIFY_OUTPUT_ROOT),
            executable=settings.VULNHUNTER_GRAPHIFY_EXECUTABLE,
            execution_enabled=False,
        )
        artifact = graphify.load_artifact(
            Path(settings.VULNHUNTER_GRAPHIFY_OUTPUT_ROOT) / "graph.json",
            repository_root=repository_root,
        )
    except GraphifyAdapterError as exc:
        graphify_row = {
            "name": "Graphify advisory graph",
            "state": "NOT_READY",
            "detail": f"No current validated graph is available ({exc.code}).",
        }
    else:
        graphify_row = {
            "name": "Graphify advisory graph",
            "state": "READY_ENABLED",
            "detail": (
                f"Validated advisory graph {artifact.graph_sha256[:12]} with "
                f"{len(artifact.nodes)} nodes; rebuild execution, hooks, and MCP are disabled."
            ),
        }

    if not settings.VULNHUNTER_GROQ_ENABLED:
        groq_row = {
            "name": "Groq advisory",
            "state": "CODE_READY_DISABLED",
            "detail": "Groq is optional and disabled. Deterministic workflows continue.",
        }
    else:
        try:
            groq = GroqProvider.from_key_file(
                Path(settings.VULNHUNTER_GROQ_API_KEY_FILE),
                approved_models=(
                    settings.VULNHUNTER_GROQ_MODEL,
                    settings.VULNHUNTER_GROQ_FALLBACK_MODEL,
                ),
                api_base=settings.VULNHUNTER_GROQ_API_BASE,
                connection_timeout_seconds=3,
                health_timeout_seconds=8,
            )
            health = groq.health()
        except GroqProviderError as exc:
            groq_row = {
                "name": "Groq advisory",
                "state": "NOT_READY",
                "detail": f"Groq configuration was rejected safely: {exc}",
            }
        else:
            ready = health.reachable and health.model is not None
            groq_row = {
                "name": "Groq advisory",
                "state": "READY_ENABLED" if ready else "NOT_READY",
                "detail": (
                    f"Approved advisory model {health.model} is available."
                    if ready
                    else health.reason
                ),
            }

    verification_row = {
        "name": "Deterministic verification",
        "state": "READY_ENABLED",
        "detail": "Verification runs inside assessments and cannot publish findings.",
    }
    return (graphify_row, groq_row, verification_row)
'''
    path.write_text(prefix + replacement, encoding="utf-8")


def patch_settings() -> None:
    path = ROOT / "vulnhunter/web/settings.py"
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        r"VULNHUNTER_OLLAMA_ENDPOINT =.*?"
        r"VULNHUNTER_OLLAMA_INFERENCE_ENABLED = env_bool\([^\n]+\)\n\n",
        re.DOTALL,
    )
    text, count = pattern.subn("", text, count=1)
    if count != 1:
        raise RuntimeError("local provider settings block was not found")
    path.write_text(text, encoding="utf-8")


def patch_environment_example() -> None:
    path = ROOT / ".env.example"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "# Advisory providers. These settings do not authorize execution. Graphify build\n"
        "# execution, Ollama inference, Groq, MCP, and Machine Oracle remain disabled until\n"
        "# their independent governance and resource gates pass.\n",
        "# Advisory components. These settings never authorize execution. Graphify, Groq,\n"
        "# MCP, and deterministic verification keep independent governance gates.\n",
    )
    text = re.sub(r"VULNHUNTER_OLLAMA_[A-Z_]+=.*\n", "", text)
    path.write_text(text, encoding="utf-8")


def patch_preview_script() -> None:
    path = ROOT / "scripts/run_local_preview.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        '    for config in (root / "local-ai.env", root / "groq.env"):\n',
        '    for config in (root / "groq.env",):\n',
    )
    text = re.sub(r'\s*os\.environ\.setdefault\("VULNHUNTER_OLLAMA_MODEL"[^\n]*\)\n', "\n", text)
    path.write_text(text, encoding="utf-8")


def remove_local_provider_files() -> None:
    for relative in (
        "vulnhunter/providers/ollama.py",
        "vulnhunter/providers/hybrid.py",
        "vulnhunter/web/management/commands/vh_verify_local_ai.py",
        "tests/unit/test_hybrid_provider.py",
    ):
        path = ROOT / relative
        path.unlink(missing_ok=True)


if __name__ == "__main__":
    patch_services()
    patch_settings()
    patch_environment_example()
    patch_preview_script()
    remove_local_provider_files()
