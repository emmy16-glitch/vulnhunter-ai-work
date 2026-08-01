from __future__ import annotations

import getpass
import os
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Store an owner-only Groq API key and verify the exact web conversation path."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--key-file",
            default=settings.VULNHUNTER_GROQ_API_KEY_FILE,
            help="Owner-only destination for the Groq API key.",
        )
        parser.add_argument(
            "--no-verify",
            action="store_true",
            help="Store the key without performing the harmless conversation readiness request.",
        )

    def handle(self, *args, **options) -> None:
        expanded = Path(str(options["key_file"])).expanduser()
        if expanded.is_symlink():
            raise CommandError("The Groq key path must not be a symbolic link.")
        path = expanded.resolve()

        key = getpass.getpass("Groq API key (input is hidden): ").strip()
        confirmation = getpass.getpass("Enter the Groq API key again: ").strip()
        if not key or key != confirmation:
            raise CommandError("The Groq API keys were empty or did not match.")
        if len(key) < 20 or len(key) > 512 or any(character.isspace() for character in key):
            raise CommandError("The Groq API key format is invalid.")

        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(f"{key}\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            temporary.replace(path)
            os.chmod(path, 0o600)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

        self.stdout.write(self.style.SUCCESS(f"Groq key stored securely at {path}."))
        if bool(options["no_verify"]):
            return
        if not settings.VULNHUNTER_GROQ_ENABLED:
            self.stdout.write(
                self.style.WARNING(
                    "The key was stored, but VULNHUNTER_GROQ_ENABLED is currently false."
                )
            )
            return

        configured_path = Path(settings.VULNHUNTER_GROQ_API_KEY_FILE).expanduser().resolve()
        if path != configured_path:
            raise CommandError(
                "Verification requires --key-file to match VULNHUNTER_GROQ_API_KEY_FILE so the "
                "web chat reads the same credential."
            )
        call_command(
            "vh_verify_llm",
            provider="groq",
            reasoning="low",
            stdout=self.stdout,
        )
