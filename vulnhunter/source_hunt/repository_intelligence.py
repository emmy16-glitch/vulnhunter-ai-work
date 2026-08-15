"""Truthful language inventory and bounded Python repository graph summary."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from vulnhunter.source_hunt.intelligence_models import (
    AnalysisCoverage,
    LanguageInventoryItem,
    RepositoryGraphSummary,
)
from vulnhunter.source_hunt.models import RepositorySnapshot
from vulnhunter.source_hunt.service import SourceHuntError

_LANGUAGE_SUFFIXES: dict[str, tuple[str, AnalysisCoverage]] = {
    ".py": ("python", AnalysisCoverage.PRODUCTION),
    ".js": ("javascript", AnalysisCoverage.INVENTORY_ONLY),
    ".jsx": ("javascript", AnalysisCoverage.INVENTORY_ONLY),
    ".ts": ("typescript", AnalysisCoverage.INVENTORY_ONLY),
    ".tsx": ("typescript", AnalysisCoverage.INVENTORY_ONLY),
    ".java": ("java", AnalysisCoverage.INVENTORY_ONLY),
    ".kt": ("kotlin", AnalysisCoverage.INVENTORY_ONLY),
    ".go": ("go", AnalysisCoverage.INVENTORY_ONLY),
    ".php": ("php", AnalysisCoverage.INVENTORY_ONLY),
    ".cs": ("csharp", AnalysisCoverage.INVENTORY_ONLY),
    ".c": ("c", AnalysisCoverage.INVENTORY_ONLY),
    ".cc": ("cpp", AnalysisCoverage.INVENTORY_ONLY),
    ".cpp": ("cpp", AnalysisCoverage.INVENTORY_ONLY),
    ".h": ("c_or_cpp_header", AnalysisCoverage.INVENTORY_ONLY),
    ".hpp": ("cpp", AnalysisCoverage.INVENTORY_ONLY),
}
_EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".local",
    }
)


class LanguageInventoryBuilder:
    @staticmethod
    def build(repository_root: Path) -> tuple[LanguageInventoryItem, ...]:
        counts: dict[tuple[str, AnalysisCoverage], int] = {}
        for path in sorted(repository_root.rglob("*")):
            relative = path.relative_to(repository_root)
            if any(part in _EXCLUDED_PARTS for part in relative.parts):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            descriptor = _LANGUAGE_SUFFIXES.get(path.suffix.lower())
            if descriptor is not None:
                counts[descriptor] = counts.get(descriptor, 0) + 1
        return tuple(
            LanguageInventoryItem(language=language, file_count=count, coverage=coverage)
            for (language, coverage), count in sorted(
                counts.items(), key=lambda item: (item[0][0], item[0][1].value)
            )
        )


class PythonRepositoryGraphBuilder:
    """Build a bounded call summary without widening deterministic attack surfaces."""

    def __init__(self, snapshot: RepositorySnapshot) -> None:
        self.snapshot = snapshot
        self.root = Path(snapshot.repository_root)

    def build(self) -> RepositoryGraphSummary:
        python_files = classes = functions = 0
        call_edges = self_method_edges = ambiguous_calls = unresolved_calls = 0
        known_functions: dict[str, int] = {}
        class_methods: dict[tuple[str, str], int] = {}
        parsed: list[ast.AST] = []

        for file in self.snapshot.files:
            if file.language != "python":
                continue
            raw = (self.root / file.path).read_bytes()
            if hashlib.sha256(raw).hexdigest() != file.sha256:
                raise SourceHuntError("repository changed while the V2 graph was being built")
            try:
                tree = ast.parse(raw.decode("utf-8"), filename=file.path)
            except (UnicodeError, SyntaxError) as exc:
                raise SourceHuntError("Python graph input could not be parsed safely") from exc
            parsed.append(tree)
            python_files += 1
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    classes += 1
                    for member in node.body:
                        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            key = (node.name, member.name)
                            class_methods[key] = class_methods.get(key, 0) + 1
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions += 1
                    known_functions[node.name] = known_functions.get(node.name, 0) + 1

        for tree in parsed:

            class Visitor(ast.NodeVisitor):
                def __init__(self) -> None:
                    self.class_stack: list[str] = []

                def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
                    self.class_stack.append(node.name)
                    self.generic_visit(node)
                    self.class_stack.pop()

                def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
                    nonlocal call_edges, self_method_edges, ambiguous_calls, unresolved_calls
                    if isinstance(node.func, ast.Name):
                        count = known_functions.get(node.func.id, 0)
                        if count == 1:
                            call_edges += 1
                        elif count > 1:
                            ambiguous_calls += 1
                        else:
                            unresolved_calls += 1
                    elif isinstance(node.func, ast.Attribute):
                        if (
                            isinstance(node.func.value, ast.Name)
                            and node.func.value.id == "self"
                            and self.class_stack
                        ):
                            count = class_methods.get((self.class_stack[-1], node.func.attr), 0)
                            if count == 1:
                                call_edges += 1
                                self_method_edges += 1
                            elif count > 1:
                                ambiguous_calls += 1
                            else:
                                unresolved_calls += 1
                        else:
                            unresolved_calls += 1
                    self.generic_visit(node)

            Visitor().visit(tree)

        return RepositoryGraphSummary(
            python_files=python_files,
            classes=classes,
            functions=functions,
            call_edges=call_edges,
            self_method_edges=self_method_edges,
            ambiguous_calls=ambiguous_calls,
            unresolved_calls=unresolved_calls,
        )
