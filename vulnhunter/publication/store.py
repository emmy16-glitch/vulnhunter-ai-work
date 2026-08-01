"""HMAC-signed append-only storage for governed publication records."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from vulnhunter.publication.models import (
    PublicationCorrection,
    PublicationManifest,
    PublicationRevocation,
    ReleaseApproval,
    ReleaseRequest,
)

_Record = TypeVar("_Record", bound=BaseModel)


class PublicationStoreError(RuntimeError):
    """A publication record failed an integrity or storage boundary."""


class PublicationStore:
    """Store signed immutable release records and derive current public status."""

    def __init__(self, root: Path, *, signing_key: bytes) -> None:
        if len(signing_key) < 16:
            raise PublicationStoreError("publication signing key is too short")
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self._signing_key = bytes(signing_key)

    def _directory(self, category: str) -> Path:
        path = self.root / category
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)
        return path

    def _signature(self, category: str, payload: dict[str, object]) -> str:
        encoded = json.dumps(
            {"category": category, "payload": payload},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hmac.new(self._signing_key, encoded, hashlib.sha256).hexdigest()

    def signed_envelope_bytes(self, category: str, record: BaseModel) -> bytes:
        payload = record.model_dump(mode="json")
        envelope = {
            "category": category,
            "payload": payload,
            "payload_sha256": record.fingerprint(),
            "signature_sha256": self._signature(category, payload),
        }
        return json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def _save(self, category: str, identifier: str, record: BaseModel) -> bool:
        destination = self._directory(category) / f"{identifier}.json"
        raw = self.signed_envelope_bytes(category, record)
        if destination.exists():
            if destination.is_symlink():
                raise PublicationStoreError("publication storage contains an unsafe symlink")
            if destination.read_bytes() == raw:
                return False
            raise PublicationStoreError(
                f"{category} record already exists with different immutable content"
            )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{identifier}-",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return True

    def _load(
        self,
        category: str,
        identifier: str,
        model: type[_Record],
    ) -> _Record:
        path = self._directory(category) / f"{identifier}.json"
        try:
            if path.is_symlink():
                raise PublicationStoreError("publication storage contains an unsafe symlink")
            envelope = json.loads(path.read_text(encoding="utf-8"))
            if envelope["category"] != category:
                raise PublicationStoreError("publication record category does not match")
            payload = envelope["payload"]
            payload_sha256 = str(envelope["payload_sha256"])
            signature = str(envelope["signature_sha256"])
        except PublicationStoreError:
            raise
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise PublicationStoreError(f"{category} record is unavailable or invalid") from exc
        if not hmac.compare_digest(signature, self._signature(category, payload)):
            raise PublicationStoreError("publication record signature verification failed")
        try:
            record = model.model_validate(payload)
        except ValidationError as exc:
            raise PublicationStoreError("publication record schema is invalid") from exc
        if record.fingerprint() != payload_sha256:
            raise PublicationStoreError("publication record digest verification failed")
        return record

    def _identifiers(self, category: str) -> tuple[str, ...]:
        directory = self._directory(category)
        identifiers: list[str] = []
        for path in sorted(directory.glob("*.json")):
            if path.is_symlink():
                raise PublicationStoreError("publication storage contains an unsafe symlink")
            if not path.is_file():
                continue
            identifiers.append(path.stem)
        return tuple(identifiers)

    def save_request(self, record: ReleaseRequest) -> bool:
        return self._save("requests", record.request_id, record)

    def load_request(self, request_id: str) -> ReleaseRequest:
        return self._load("requests", request_id, ReleaseRequest)

    def save_approval(self, record: ReleaseApproval) -> bool:
        return self._save("approvals", record.approval_id, record)

    def load_approval(self, approval_id: str) -> ReleaseApproval:
        return self._load("approvals", approval_id, ReleaseApproval)

    def save_publication(self, record: PublicationManifest) -> bool:
        return self._save("publications", record.publication_id, record)

    def load_publication(self, publication_id: str) -> PublicationManifest:
        return self._load("publications", publication_id, PublicationManifest)

    def list_publications_for_finding(
        self,
        finding_id: str,
    ) -> tuple[PublicationManifest, ...]:
        """Return verified publications for one finding in deterministic time order."""

        records = [
            self.load_publication(identifier) for identifier in self._identifiers("publications")
        ]
        matched = [record for record in records if record.source_finding_id == finding_id]
        matched.sort(key=lambda item: (item.published_at, item.publication_id))
        return tuple(matched)

    def latest_publication_for_finding(
        self,
        finding_id: str,
    ) -> PublicationManifest | None:
        records = self.list_publications_for_finding(finding_id)
        return records[-1] if records else None

    def save_correction(self, record: PublicationCorrection) -> bool:
        return self._save(
            "corrections",
            record.superseded_publication_id,
            record,
        )

    def load_correction(self, publication_id: str) -> PublicationCorrection:
        return self._load("corrections", publication_id, PublicationCorrection)

    def save_revocation(self, record: PublicationRevocation) -> bool:
        return self._save("revocations", record.publication_id, record)

    def load_revocation(self, publication_id: str) -> PublicationRevocation:
        return self._load("revocations", publication_id, PublicationRevocation)

    def _rollback_exact(self, category: str, identifier: str, record: BaseModel) -> None:
        path = self._directory(category) / f"{identifier}.json"
        if not path.exists():
            return
        if path.is_symlink():
            raise PublicationStoreError("publication storage contains an unsafe symlink")
        expected = self.signed_envelope_bytes(category, record)
        if path.read_bytes() != expected:
            raise PublicationStoreError(
                "publication rollback refused to remove different immutable content"
            )
        path.unlink()

    def rollback_publication(self, record: PublicationManifest) -> None:
        self._rollback_exact("publications", record.publication_id, record)

    def rollback_correction(self, record: PublicationCorrection) -> None:
        self._rollback_exact("corrections", record.superseded_publication_id, record)

    def rollback_revocation(self, record: PublicationRevocation) -> None:
        self._rollback_exact("revocations", record.publication_id, record)

    def status(self, publication_id: str) -> str:
        self.load_publication(publication_id)
        revocation_path = self._directory("revocations") / f"{publication_id}.json"
        if revocation_path.exists():
            self.load_revocation(publication_id)
            return "revoked"
        correction_path = self._directory("corrections") / f"{publication_id}.json"
        if correction_path.exists():
            self.load_correction(publication_id)
            return "superseded"
        return "published"


__all__ = ["PublicationStore", "PublicationStoreError"]
