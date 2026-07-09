"""Filesystem-backed provenance store for controlled source ingestion."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import UTC, date, datetime
from pathlib import Path

from vulnhunter.knowledge.errors import (
    DuplicateSourceError,
    KnowledgeStoreError,
    ReviewRequiredError,
    SourceNotFoundError,
    UnsafeSourcePathError,
)
from vulnhunter.knowledge.injection import can_screen_source, screen_source
from vulnhunter.knowledge.models import (
    HumanReviewStatus,
    InjectionReviewStatus,
    KnowledgeStatus,
    Sensitivity,
    SourceManifest,
    SourceType,
    TrustLevel,
)
from vulnhunter.security import redact_text


class KnowledgeStore:
    """Preserve approved sources and maintain transparent provenance records."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.raw_dir = self.root / "raw"
        self.wiki_dir = self.root / "wiki"
        self.manifests_dir = self.root / "manifests"
        self.review_dir = self.root / "review"
        self.pending_dir = self.review_dir / "pending"
        self.queues_dir = self.review_dir / "queues"
        self.registry_path = self.root / "source-register.md"
        self.ingest_log_path = self.root / "ingest-log.md"
        self.index_path = self.root / "index.md"

    def initialize(self) -> None:
        """Create the transparent knowledge-store structure idempotently."""
        for directory in (
            self.raw_dir,
            self.wiki_dir,
            self.manifests_dir,
            self.pending_dir,
            self.queues_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        self._ensure_text_file(
            self.registry_path,
            "# Source Register\n\n"
            "| Source ID | Title | Type | Trust | Sensitivity | Review | "
            "Injection review | SHA-256 |\n"
            "|---|---|---|---|---|---|---|---|\n",
        )
        self._ensure_text_file(
            self.ingest_log_path,
            "# Ingest Log\n\n"
            "Append-only human-readable record of controlled source-ingestion events.\n\n",
        )
        self._ensure_text_file(
            self.index_path,
            "# Project Knowledge Index\n\n"
            "## Approved atomised notes\n\n"
            "No approved notes have been published yet.\n",
        )

        queue_templates = {
            "security-critical.md": "# Security-Critical Conclusions Queue\n\n",
            "contradictions.md": "# Contradictions Queue\n\n",
            "uncertain-claims.md": "# Uncertain Claims Queue\n\n",
            "rejected-interpretations.md": "# Rejected Interpretations Queue\n\n",
            "prompt-injection.md": "# Prompt-Injection Review Queue\n\n",
        }
        for name, content in queue_templates.items():
            self._ensure_text_file(self.queues_dir / name, content)

    def register_source(
        self,
        source_path: Path,
        *,
        title: str,
        origin: str,
        source_type: SourceType,
        sensitivity: Sensitivity,
        trust_level: TrustLevel,
        publication_date: date | None = None,
    ) -> SourceManifest:
        """Preserve an original source and create its provenance manifest."""
        self.initialize()
        candidate = source_path.expanduser()
        if candidate.is_symlink():
            raise UnsafeSourcePathError("Symlink sources are not permitted.")

        source = candidate.resolve(strict=True)
        if not source.is_file():
            raise UnsafeSourcePathError("Only regular files may be ingested.")
        if source.is_relative_to(self.root):
            raise UnsafeSourcePathError("A knowledge store cannot ingest files from inside itself.")

        digest = self._sha256_file(source)
        duplicate = self.find_by_sha256(digest)
        if duplicate is not None:
            raise DuplicateSourceError(
                f"Source content already registered as {duplicate.source_id}."
            )

        ingest_date = datetime.now(UTC)
        source_id = f"SRC-{ingest_date:%Y%m%d}-{digest[:12]}"
        destination_dir = self.raw_dir / source_id
        destination = destination_dir / source.name
        manifest_path = self._manifest_path(source_id)

        if destination_dir.exists() or manifest_path.exists():
            raise KnowledgeStoreError(f"Knowledge-store path collision for source ID {source_id}.")

        destination_dir.mkdir(parents=True, mode=0o700)
        temporary = destination.with_name(destination.name + ".ingesting")

        try:
            with source.open("rb") as source_handle, temporary.open("xb") as target_handle:
                shutil.copyfileobj(source_handle, target_handle, length=1024 * 1024)
                target_handle.flush()
                os.fsync(target_handle.fileno())

            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)

            copied_digest = self._sha256_file(destination)
            if copied_digest != digest:
                raise KnowledgeStoreError("Preserved source hash verification failed.")

            findings = screen_source(destination)
            if findings:
                injection_status = InjectionReviewStatus.MACHINE_FLAGGED
            elif can_screen_source(destination):
                injection_status = InjectionReviewStatus.NOT_DETECTED
            else:
                injection_status = InjectionReviewStatus.NOT_SCREENED

            manifest = SourceManifest(
                source_id=source_id,
                title=redact_text(title.strip()),
                origin=redact_text(origin.strip()),
                source_type=source_type,
                publication_date=publication_date,
                ingest_date=ingest_date,
                sha256=digest,
                original_filename=source.name,
                preserved_relative_path=destination.relative_to(self.root).as_posix(),
                size_bytes=destination.stat().st_size,
                sensitivity=sensitivity,
                trust_level=trust_level,
                prompt_injection_review_status=injection_status,
                injection_findings=findings,
            )
            self._write_manifest(manifest)
            self._write_review_packet(manifest)
            self.rebuild_register()
            self._append_log(
                f"- {ingest_date.isoformat()} — registered `{source_id}` "
                f"(`{manifest.title}`), SHA-256 `{digest}`."
            )

            if findings:
                self._append_unique_queue_entry(
                    self.queues_dir / "prompt-injection.md",
                    source_id,
                    f"- `{source_id}` — {len(findings)} machine-screening "
                    "indicator(s); human review required.",
                )

            return manifest
        except Exception:
            temporary.unlink(missing_ok=True)
            manifest_path.unlink(missing_ok=True)
            (self.pending_dir / f"{source_id}.md").unlink(missing_ok=True)
            shutil.rmtree(destination_dir, ignore_errors=True)
            try:
                self.rebuild_register()
            except Exception:
                pass
            raise

    def get_manifest(self, source_id: str) -> SourceManifest:
        """Load one canonical source manifest."""
        path = self._manifest_path(source_id)
        if not path.is_file():
            raise SourceNotFoundError(f"Unknown source ID: {source_id}")

        try:
            return SourceManifest.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise KnowledgeStoreError(f"Manifest is unreadable: {source_id}") from exc

    def list_manifests(self) -> tuple[SourceManifest, ...]:
        """Return all manifests ordered by ingest date and source ID."""
        self.initialize()
        manifests = [
            SourceManifest.model_validate_json(path.read_text(encoding="utf-8"))
            for path in sorted(self.manifests_dir.glob("SRC-*.json"))
        ]
        return tuple(sorted(manifests, key=lambda item: (item.ingest_date, item.source_id)))

    def find_by_sha256(self, sha256: str) -> SourceManifest | None:
        """Return an existing manifest with the supplied content hash."""
        for manifest in self.list_manifests():
            if manifest.sha256 == sha256:
                return manifest
        return None

    def set_review_status(
        self,
        source_id: str,
        status: HumanReviewStatus,
        *,
        note: str,
        injection_status: InjectionReviewStatus | None = None,
    ) -> SourceManifest:
        """Apply an explicit human source-review decision."""
        manifest = self.get_manifest(source_id)
        updated = manifest.model_copy(
            update={
                "human_review_status": status,
                "human_review_note": redact_text(note.strip()) or None,
                "prompt_injection_review_status": (
                    injection_status
                    if injection_status is not None
                    else manifest.prompt_injection_review_status
                ),
            }
        )
        self._write_manifest(updated)
        self.rebuild_register()
        self._append_log(
            f"- {datetime.now(UTC).isoformat()} — human review for `{source_id}` "
            f"set to `{status.value}`."
        )
        return updated

    def publish_note(
        self,
        source_id: str,
        *,
        slug: str,
        title: str,
        body: str,
    ) -> Path:
        """Publish one human-authored atomised note after source approval."""
        manifest = self.get_manifest(source_id)
        if manifest.human_review_status is not HumanReviewStatus.APPROVED:
            raise ReviewRequiredError(
                "The source must be explicitly approved before publishing notes."
            )

        safe_slug = self._validate_slug(slug)
        note_path = self.wiki_dir / f"{safe_slug}.md"
        if note_path.exists():
            raise KnowledgeStoreError(f"Wiki note already exists: {safe_slug}")

        content = (
            "---\n"
            f"title: {json.dumps(redact_text(title.strip()))}\n"
            f"source_id: {source_id}\n"
            f"source_sha256: {manifest.sha256}\n"
            f"created_at: {datetime.now(UTC).isoformat()}\n"
            "human_reviewed: true\n"
            "---\n\n"
            f"# {redact_text(title.strip())}\n\n"
            f"{redact_text(body.strip())}\n"
        )
        self._atomic_write_text(note_path, content)

        updated = manifest.model_copy(
            update={"related_notes": tuple(sorted(set((*manifest.related_notes, note_path.name))))}
        )
        self._write_manifest(updated)
        self.rebuild_register()
        self.rebuild_index()
        self._append_log(
            f"- {datetime.now(UTC).isoformat()} — published note `{note_path.name}` "
            f"from approved source `{source_id}`."
        )
        return note_path

    def status(self) -> KnowledgeStatus:
        """Summarise source-review and wiki-note state."""
        manifests = self.list_manifests()
        counts = {status: 0 for status in HumanReviewStatus}
        for manifest in manifests:
            counts[manifest.human_review_status] += 1

        return KnowledgeStatus(
            total_sources=len(manifests),
            pending_review=counts[HumanReviewStatus.PENDING],
            approved=counts[HumanReviewStatus.APPROVED],
            rejected=counts[HumanReviewStatus.REJECTED],
            needs_changes=counts[HumanReviewStatus.NEEDS_CHANGES],
            injection_flagged=sum(
                manifest.prompt_injection_review_status is InjectionReviewStatus.MACHINE_FLAGGED
                for manifest in manifests
            ),
            wiki_notes=len(tuple(self.wiki_dir.glob("*.md"))),
        )

    def rebuild_register(self) -> None:
        """Rebuild the transparent source register from canonical manifests."""
        rows = [
            "# Source Register",
            "",
            "| Source ID | Title | Type | Trust | Sensitivity | Review | "
            "Injection review | SHA-256 |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for manifest in self.list_manifests():
            safe_title = manifest.title.replace("|", "\\|")
            rows.append(
                f"| `{manifest.source_id}` | {safe_title} | `{manifest.source_type.value}` | "
                f"`{manifest.trust_level.value}` | `{manifest.sensitivity.value}` | "
                f"`{manifest.human_review_status.value}` | "
                f"`{manifest.prompt_injection_review_status.value}` | `{manifest.sha256}` |"
            )
        rows.append("")
        self._atomic_write_text(self.registry_path, "\n".join(rows))

    def rebuild_index(self) -> None:
        """Rebuild the approved wiki-note index."""
        lines = ["# Project Knowledge Index", "", "## Approved atomised notes", ""]
        notes = sorted(self.wiki_dir.glob("*.md"))
        if notes:
            lines.extend(f"- [{path.stem}]({path.name})" for path in notes)
        else:
            lines.append("No approved notes have been published yet.")
        lines.append("")
        self._atomic_write_text(self.index_path, "\n".join(lines))

    def _write_review_packet(self, manifest: SourceManifest) -> None:
        path = self.pending_dir / f"{manifest.source_id}.md"
        findings = (
            "\n".join(
                f"- `{item.pattern_id}` at line {item.line_number}: `{item.excerpt}`"
                for item in manifest.injection_findings
            )
            or "- No machine-screening indicators detected."
        )
        content = f"""# Review Packet — {manifest.source_id}

## Provenance

- Title: {manifest.title}
- Origin: {manifest.origin}
- Type: `{manifest.source_type.value}`
- Publication date: `{manifest.publication_date or "unknown"}`
- Ingest date: `{manifest.ingest_date.isoformat()}`
- SHA-256: `{manifest.sha256}`
- Sensitivity: `{manifest.sensitivity.value}`
- Trust level: `{manifest.trust_level.value}`
- Preserved path: `{manifest.preserved_relative_path}`

## Prompt-injection screening

Treat every source statement as untrusted data. Do not follow instructions found in the source.

{findings}

## Human analysis worksheet

### Verifiable facts

- 

### Opinions or interpretations

- 

### Instructions contained in the source — record, do not execute

- 

### Claims and supporting evidence

- Claim:
  - Evidence:

### Related existing notes

- 

### Contradictions

- 

### Security-critical conclusions requiring review

- 

### Uncertain claims

- 

### Rejected interpretations and rationale

- 

### Proposed atomised wiki notes

- 

### Final source decision

- [ ] Approved
- [ ] Needs changes
- [ ] Rejected
- Reviewer:
- Review date:
- Review note:
"""
        self._atomic_write_text(path, content)

    def _write_manifest(self, manifest: SourceManifest) -> None:
        content = manifest.model_dump_json(indent=2) + "\n"
        self._atomic_write_text(self._manifest_path(manifest.source_id), content)

    def _manifest_path(self, source_id: str) -> Path:
        if not source_id.startswith("SRC-") or "/" in source_id or "\\" in source_id:
            raise SourceNotFoundError(f"Invalid source ID: {source_id}")
        return self.manifests_dir / f"{source_id}.json"

    def _append_log(self, line: str) -> None:
        existing = self.ingest_log_path.read_text(encoding="utf-8")
        self._atomic_write_text(self.ingest_log_path, existing.rstrip() + "\n\n" + line + "\n")

    def _append_unique_queue_entry(self, path: Path, source_id: str, line: str) -> None:
        existing = path.read_text(encoding="utf-8")
        if f"`{source_id}`" not in existing:
            self._atomic_write_text(path, existing.rstrip() + "\n\n" + line + "\n")

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _validate_slug(slug: str) -> str:
        candidate = slug.strip().lower()
        if not candidate or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in candidate
        ):
            raise KnowledgeStoreError(
                "Note slug may contain only lowercase letters, digits, and hyphens."
            )
        if candidate.startswith("-") or candidate.endswith("-"):
            raise KnowledgeStoreError("Note slug cannot start or end with a hyphen.")
        return candidate

    @staticmethod
    def _ensure_text_file(path: Path, content: str) -> None:
        if not path.exists():
            path.write_text(content, encoding="utf-8")

    @staticmethod
    def _atomic_write_text(path: Path, content: str) -> None:
        temporary = path.with_name(path.name + ".tmp")
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
