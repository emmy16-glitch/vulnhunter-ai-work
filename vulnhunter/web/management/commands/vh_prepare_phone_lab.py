from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.service import issue_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import ScopeValidationError
from vulnhunter.scope import validate_target
from vulnhunter.web.assessment_workflow import (
    AssessmentWorkflowError,
    bind_nuclei_authorization,
    load_nuclei_authorization,
)


class Command(BaseCommand):
    help = "Create or reuse the exact passive authorization for the Codespaces phone lab."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--target-url", required=True)
        parser.add_argument("--owner", required=True)
        parser.add_argument("--approved-by", required=True)
        parser.add_argument("--valid-hours", type=int, default=12)

    def handle(self, *args, **options) -> None:
        target_url = options["target_url"].strip()
        owner = options["owner"].strip()
        approved_by = options["approved_by"].strip()
        valid_hours = int(options["valid_hours"])
        if not owner or not approved_by:
            raise CommandError("owner and approved-by must not be blank")
        if owner.casefold() == approved_by.casefold():
            raise CommandError("the phone lab operator and approver must be different identities")
        if not 1 <= valid_hours <= 72:
            raise CommandError("valid-hours must be between 1 and 72")

        try:
            target = validate_target(target_url)
            parsed = urlsplit(target.normalized_url)
            address = ipaddress.ip_address(parsed.hostname or "")
        except (OSError, ScopeValidationError, ValueError) as exc:
            raise CommandError(str(exc)) from exc
        if not isinstance(address, ipaddress.IPv4Address):
            raise CommandError("the phone lab requires a literal IPv4 target")
        allowed = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if (
            address.is_loopback
            or address.is_link_local
            or not any(address in item for item in allowed)
        ):
            raise CommandError("the phone lab target must be a non-loopback RFC1918 address")

        now = datetime.now(UTC)
        store = AuthorizationStore.from_path(Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE))
        store.initialize()
        record = next(
            (
                item
                for item in store.list(limit=250)
                if item.status == "active"
                and item.owner.casefold() == owner.casefold()
                and item.target_url == target.normalized_url
                and now < item.expires_at
            ),
            None,
        )
        if record is None:
            record = issue_authorization(
                store,
                target,
                owner=owner,
                approved_by=approved_by,
                purpose="Phone-only Codespaces private laboratory passive assessment.",
                evidence_reference="codespaces-phone-lab-self-owned-target",
                expires_at=now + timedelta(hours=valid_hours),
                limits=AuthorizationLimits(
                    maximum_pages=2,
                    maximum_depth=0,
                    maximum_requests=10,
                    minimum_request_delay_seconds=1,
                ),
                now=now,
            )
            created = True
        else:
            created = False

        try:
            _, engagement = load_nuclei_authorization(store, record.authorization_id)
            if (
                "passive" not in engagement.approved_scan_profiles
                or not engagement.private_network_approved
            ):
                raise CommandError(
                    "the existing activation binding is not valid for this phone lab"
                )
        except AssessmentWorkflowError:
            bind_nuclei_authorization(
                store,
                authorization_id=record.authorization_id,
                approved_profiles=("passive",),
                private_network_approved=True,
                recorded_by=approved_by,
                approval_basis=(
                    "Operator-invoked Codespaces phone lab setup for the exact self-owned "
                    "RFC1918 target and reviewed passive template."
                ),
                now=now,
            )

        verb = "Created" if created else "Reused"
        self.stdout.write(self.style.SUCCESS(f"{verb} phone-lab authorization."))
        self.stdout.write(f"Authorization ID: {record.authorization_id}")
        self.stdout.write(f"Target: {record.target_url}")
        self.stdout.write(f"Owner/operator: {record.owner}")
        self.stdout.write(f"Independent approver: {record.approved_by}")
        self.stdout.write(f"Expires: {record.expires_at.isoformat()}")
