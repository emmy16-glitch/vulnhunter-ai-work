from __future__ import annotations

import getpass
import hashlib
import os
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vulnhunter.providers import (
    GroqProvider,
    GroqProviderError,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
)


class Command(BaseCommand):
    help = "Store an owner-only Groq API key and verify bounded advisory inference."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--key-file",
            default=settings.VULNHUNTER_GROQ_API_KEY_FILE,
            help="Owner-only destination for the Groq API key.",
        )
        parser.add_argument(
            "--no-verify",
            action="store_true",
            help="Store the key without performing the harmless readiness request.",
        )

    def handle(self, *args, **options) -> None:
        path = Path(str(options["key_file"])).expanduser().resolve()
        if path.is_symlink():
            raise CommandError("The Groq key path must not be a symbolic link.")

        key = getpass.getpass("Groq API key (input is hidden): ").strip()
        confirmation = getpass.getpass("Enter the Groq API key again: ").strip()
        if not key or key != confirmation:
            raise CommandError("The Groq API keys were empty or did not match.")
        if len(key) < 20 or any(character.isspace() for character in key):
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

        content = (
            "Return a candidate analysis whose content is exactly VULNHUNTER_GROQ_READY. "
            "Do not request tools, credentials, private data, approval, or execution."
        )
        raw = content.encode("utf-8")
        invocation = ProviderInvocation(
            invocation_id="groq-workspace-readiness",
            request_id="groq-workspace-readiness",
            provider=ProviderKind.GROQ_ADVISORY,
            model=settings.VULNHUNTER_GROQ_MODEL,
            capability=ProviderCapability.CLASSIFICATION,
            input_sha256=hashlib.sha256(raw).hexdigest(),
            maximum_input_characters=2_000,
            maximum_output_characters=1_000,
            maximum_input_bytes=4_000,
            maximum_output_bytes=4_000,
            maximum_input_tokens=1_000,
            maximum_output_tokens=800,
            timeout_seconds=min(settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS, 60),
        )
        try:
            provider = GroqProvider.from_key_file(
                path,
                approved_models=(
                    settings.VULNHUNTER_GROQ_MODEL,
                    settings.VULNHUNTER_GROQ_FALLBACK_MODEL,
                ),
                api_base=settings.VULNHUNTER_GROQ_API_BASE,
            )
            health = provider.health()
            if not health.reachable or not health.model:
                raise CommandError(health.reason)
            if health.model != invocation.model:
                invocation = invocation.model_copy(update={"model": health.model})
            response = provider.invoke(invocation, content)
        except GroqProviderError as exc:
            raise CommandError(f"Groq configuration was rejected safely: {exc}") from exc
        if response.output_kind == ProviderOutputKind.ABSTAIN:
            raise CommandError(response.safe_error or "Groq abstained during verification.")
        if "VULNHUNTER_GROQ_READY" not in response.content:
            raise CommandError("Groq returned valid data but missed the readiness marker.")
        self.stdout.write(
            self.style.SUCCESS(
                f"Groq advisory verified with model {response.model}; output remains untrusted."
            )
        )
