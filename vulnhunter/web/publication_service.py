"""Deployment-owned configuration for governed final-report publication."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

from vulnhunter.publication import (
    PublicationDestinationConfig,
    PublicationService,
    PublicationServiceError,
    PublicationStore,
)
from vulnhunter.reports import FinalReportFormat
from vulnhunter.web.final_report_service import final_report_store
from vulnhunter.web.services import governance_store


@dataclass(frozen=True)
class PublicationRuntimeConfig:
    destinations: tuple[PublicationDestinationConfig, ...]
    release_authority_ids: frozenset[str]


def publication_state_root() -> Path:
    configured = os.environ.get(
        "VULNHUNTER_PUBLICATION_STATE_ROOT",
        str(
            getattr(
                settings,
                "VULNHUNTER_PUBLICATION_STATE_ROOT",
                Path(settings.VULNHUNTER_TASK_GRAPH_ROOT) / "publication",
            )
        ),
    )
    return Path(configured)


def _owner_private_file(path: Path, *, label: str) -> bytes:
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise PublicationServiceError(f"{label} must be a regular file")
        if metadata.st_mode & 0o077:
            raise PublicationServiceError(f"{label} must be owner-private")
        return path.read_bytes()
    except PublicationServiceError:
        raise
    except OSError as exc:
        raise PublicationServiceError(f"{label} is unavailable") from exc


def publication_signing_key_file() -> Path | None:
    configured = os.environ.get(
        "VULNHUNTER_PUBLICATION_SIGNING_KEY_FILE",
        str(getattr(settings, "VULNHUNTER_PUBLICATION_SIGNING_KEY_FILE", "")),
    ).strip()
    return Path(configured).expanduser().resolve() if configured else None


def publication_signing_key() -> bytes:
    path = publication_signing_key_file()
    if path is None:
        raise PublicationServiceError(
            "publication requires an owner-private signing-key file"
        )
    key = _owner_private_file(path, label="publication signing key").strip()
    if len(key) < 32:
        raise PublicationServiceError(
            "publication signing key must contain at least 32 bytes"
        )
    return key


def publication_config_file() -> Path | None:
    configured = os.environ.get(
        "VULNHUNTER_PUBLICATION_CONFIG_FILE",
        str(getattr(settings, "VULNHUNTER_PUBLICATION_CONFIG_FILE", "")),
    ).strip()
    return Path(configured).expanduser().resolve() if configured else None


def publication_runtime_config() -> PublicationRuntimeConfig:
    path = publication_config_file()
    if path is None:
        raise PublicationServiceError(
            "publication requires a deployment-owned configuration file"
        )
    raw = _owner_private_file(path, label="publication configuration")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicationServiceError("publication configuration is invalid JSON") from exc
    if not isinstance(data, dict):
        raise PublicationServiceError("publication configuration must be an object")

    raw_authorities = data.get("release_authority_ids")
    if not isinstance(raw_authorities, list) or len(raw_authorities) < 3:
        raise PublicationServiceError(
            "publication configuration requires at least three release authorities"
        )
    authorities = frozenset(
        str(item).strip().casefold() for item in raw_authorities if str(item).strip()
    )
    if len(authorities) < 3:
        raise PublicationServiceError(
            "publication configuration requires three distinct release authorities"
        )

    raw_destinations = data.get("destinations")
    if not isinstance(raw_destinations, list) or not raw_destinations:
        raise PublicationServiceError(
            "publication configuration requires at least one destination"
        )
    destinations: list[PublicationDestinationConfig] = []
    for item in raw_destinations:
        if not isinstance(item, dict):
            raise PublicationServiceError("publication destination entry must be an object")
        if str(item.get("kind") or "local_directory") != "local_directory":
            raise PublicationServiceError(
                "only deployment-owned local-directory publication is currently supported"
            )
        try:
            formats = tuple(
                FinalReportFormat(str(value).strip().casefold())
                for value in item["allowed_formats"]
            )
            destination = PublicationDestinationConfig(
                destination_id=str(item["destination_id"]).strip().casefold(),
                label=str(item["label"]).strip(),
                root=Path(str(item["root"])),
                allowed_formats=formats,
            )
            destination.policy()
        except (KeyError, TypeError, ValueError) as exc:
            raise PublicationServiceError(
                "publication destination configuration is invalid"
            ) from exc
        destinations.append(destination)
    if len({item.destination_id for item in destinations}) != len(destinations):
        raise PublicationServiceError("publication destination IDs must be unique")
    return PublicationRuntimeConfig(
        destinations=tuple(destinations),
        release_authority_ids=authorities,
    )


def publication_store() -> PublicationStore:
    return PublicationStore(
        publication_state_root(),
        signing_key=publication_signing_key(),
    )


def publication_store_if_configured() -> PublicationStore | None:
    if publication_signing_key_file() is None:
        return None
    return publication_store()


def publication_service() -> PublicationService:
    runtime = publication_runtime_config()
    return PublicationService(
        report_store=final_report_store(),
        governance_store=governance_store(),
        publication_store=publication_store(),
        destinations=runtime.destinations,
        release_authority_ids=runtime.release_authority_ids,
    )


__all__ = [
    "PublicationRuntimeConfig",
    "publication_config_file",
    "publication_runtime_config",
    "publication_service",
    "publication_signing_key",
    "publication_signing_key_file",
    "publication_state_root",
    "publication_store",
    "publication_store_if_configured",
]
