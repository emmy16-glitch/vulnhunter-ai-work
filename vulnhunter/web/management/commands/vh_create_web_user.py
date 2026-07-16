from __future__ import annotations

from getpass import getpass

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction

from vulnhunter.web.models import WebUserMapping


class Command(BaseCommand):
    help = "Create a Django web user and explicit VulnHunter identity mapping."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--username", required=True)
        parser.add_argument("--governance-identity", default="")
        parser.add_argument("--product-role", action="append", dest="product_roles", default=[])
        parser.add_argument("--registry-role", default="")
        parser.add_argument("--registry-skill", default="")

    def handle(self, *args, **options) -> None:
        username = options["username"].strip()
        if not username:
            raise CommandError("username is required")
        password = getpass("Password: ")
        confirmation = getpass("Confirm password: ")
        if not password.strip():
            raise CommandError("password must not be empty")
        if password != confirmation:
            raise CommandError("passwords did not match")

        User = get_user_model()
        if User.objects.filter(username=username).exists():
            raise CommandError(f"User already exists: {username}")
        try:
            validate_password(password, user=User(username=username))
            with transaction.atomic():
                user = User.objects.create_user(username=username, password=password)
                mapping = WebUserMapping(
                    user=user,
                    governance_identity_id=options["governance_identity"],
                    product_roles=options["product_roles"],
                    registry_role_id=options["registry_role"],
                    registry_skill_id=options["registry_skill"],
                )
                mapping.full_clean()
                mapping.save()
        except ValidationError as exc:
            raise CommandError("; ".join(exc.messages)) from exc
        except IntegrityError as exc:
            raise CommandError("web user or mapping could not be created safely") from exc
        self.stdout.write(self.style.SUCCESS(f"Created web user {username}."))
