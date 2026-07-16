from __future__ import annotations

from collections.abc import Iterable

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


class NewAssessmentForm(forms.Form):
    """Create a bounded launch request from stored authorization and profile records."""

    authorization_id = forms.ChoiceField(label="Authorization")
    profile_id = forms.ChoiceField(label="Assessment profile")
    objective = forms.CharField(
        label="Assessment objective",
        max_length=500,
        required=False,
        widget=forms.Textarea(
            attrs={
                "rows": 3,
                "placeholder": "Optional: describe the approved outcome for this assessment.",
            }
        ),
    )
    acknowledge_scope = forms.BooleanField(
        label="I confirm that this launch request must remain within the selected authorization.",
        required=True,
    )

    def __init__(
        self,
        *args,
        authorization_rows: Iterable[dict[str, str]] = (),
        profile_rows: Iterable[dict[str, str]] = (),
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.fields["authorization_id"].choices = tuple(
            (row["id"], row["label"]) for row in authorization_rows
        )
        self.fields["profile_id"].choices = tuple((row["id"], row["name"]) for row in profile_rows)

    def clean_objective(self) -> str:
        return str(self.cleaned_data.get("objective") or "").strip()


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
