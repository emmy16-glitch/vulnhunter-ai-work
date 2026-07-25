from __future__ import annotations

from django.core.management.base import BaseCommand

from vulnhunter.web.conversation_uploads import prune_stale_apk_uploads


class Command(BaseCommand):
    help = "Remove expired resumable APK upload fragments from the private staging area."

    def handle(self, *args, **options) -> None:
        removed = prune_stale_apk_uploads()
        self.stdout.write(self.style.SUCCESS(f"Removed {removed} expired APK upload fragment(s)."))
