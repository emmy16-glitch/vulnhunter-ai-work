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


class MobileApkUploadForm(forms.Form):
    apk_file = forms.FileField(
        label="Android APK",
        help_text="Upload an APK for content-addressed static analysis preparation.",
        widget=forms.ClearableFileInput(
            attrs={"accept": ".apk,application/vnd.android.package-archive"}
        ),
    )

    def clean_apk_file(self):
        uploaded = self.cleaned_data["apk_file"]
        if not uploaded.name.lower().endswith(".apk"):
            raise forms.ValidationError("The uploaded file must use the .apk extension.")
        if uploaded.size <= 0:
            raise forms.ValidationError("The uploaded APK is empty.")
        return uploaded
