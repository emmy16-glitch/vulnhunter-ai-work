from __future__ import annotations

import getpass
import os
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Store an owner-only Hugging Face token and verify bounded advisory inference."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--token-file",
            default=settings.VULNHUNTER_HUGGINGFACE_TOKEN_FILE,
            help="Owner-only destination for the Hugging Face token.",
        )
        parser.add_argument("--no-verify", action="store_true")

    def handle(self, *args, **options) -> None:
        path = Path(str(options["token_file"])).expanduser().resolve()
        if path.is_symlink():
            raise CommandError("The Hugging Face token path must not be a symbolic link.")
        token = getpass.getpass("Hugging Face token (input is hidden): ").strip()
        confirmation = getpass.getpass("Enter the Hugging Face token again: ").strip()
        if not token or token != confirmation:
            raise CommandError("The Hugging Face tokens were empty or did not match.")
        if len(token) < 20 or any(character.isspace() for character in token):
            raise CommandError("The Hugging Face token format is invalid.")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(f"{token}\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            temporary.replace(path)
            os.chmod(path, 0o600)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        self.stdout.write(self.style.SUCCESS(f"Hugging Face token stored securely at {path}."))
        if bool(options["no_verify"]):
            return
        if not settings.VULNHUNTER_HUGGINGFACE_ENABLED:
            self.stdout.write(
                self.style.WARNING(
                    "The token was stored, but VULNHUNTER_HUGGINGFACE_ENABLED is false."
                )
            )
            return
        call_command("vh_verify_huggingface")
