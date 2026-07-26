from __future__ import annotations

from django import forms
from django.contrib.auth.forms import AuthenticationForm


class VulnHunterAuthenticationForm(AuthenticationForm):
    username = forms.CharField(
        label="Username",
        max_length=150,
        widget=forms.TextInput(attrs={"autocomplete": "username"}),
    )
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )


class StopRunForm(forms.Form):
    reason = forms.CharField(
        label="Stop reason",
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 4}),
        help_text="Explain the exact bounded reason for stopping the run.",
    )
