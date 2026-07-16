from __future__ import annotations

import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

_ROLE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class WebUserMapping(models.Model):
    """Narrow bridge from Django sessions to VulnHunter identities and roles."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="vulnhunter_mapping",
    )
    governance_identity_id = models.CharField(max_length=64, blank=True)
    product_roles = models.JSONField(default=list)
    registry_role_id = models.CharField(max_length=128, blank=True)
    registry_skill_id = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self) -> None:
        if not isinstance(self.product_roles, list):
            raise ValidationError({"product_roles": "product_roles must be a list of role IDs."})
        normalized: list[str] = []
        for role_id in self.product_roles:
            if not isinstance(role_id, str) or _ROLE_PATTERN.fullmatch(role_id) is None:
                raise ValidationError({"product_roles": f"Invalid role identifier: {role_id!r}"})
            if role_id not in normalized:
                normalized.append(role_id)
        self.product_roles = normalized
        for field_name in ("governance_identity_id", "registry_role_id", "registry_skill_id"):
            value = getattr(self, field_name).strip()
            setattr(self, field_name, value)

    def __str__(self) -> str:
        return f"{self.user.username} -> {','.join(self.product_roles) or 'unmapped'}"
