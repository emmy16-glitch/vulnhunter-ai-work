from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.web.models import WebUserMapping


class Command(BaseCommand):
    help = "Update the VulnHunter mapping for an existing Django web user."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--username", required=True)
        parser.add_argument("--governance-identity", default="")
        parser.add_argument("--product-role", action="append", dest="product_roles", default=[])
        parser.add_argument("--registry-role", default="")
        parser.add_argument("--registry-skill", default="")

    def handle(self, *args, **options) -> None:
        username = options["username"].strip()
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist as exc:
            raise CommandError(f"Unknown user: {username}") from exc
        mapping, _ = WebUserMapping.objects.get_or_create(user=user)
        mapping.governance_identity_id = options["governance_identity"]
        mapping.product_roles = options["product_roles"]
        mapping.registry_role_id = options["registry_role"]
        mapping.registry_skill_id = options["registry_skill"]
        mapping.full_clean()
        mapping.save()
        self.stdout.write(self.style.SUCCESS(f"Updated mapping for {username}."))
