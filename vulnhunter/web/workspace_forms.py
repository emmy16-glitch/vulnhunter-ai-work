from __future__ import annotations

from django import forms


_SECRET_WIDGET = forms.PasswordInput(
    render_value=False,
    attrs={
        "autocomplete": "current-password",
        "spellcheck": "false",
    },
)


class GovernedReviewForm(forms.Form):
    outcome = forms.ChoiceField(
        choices=(
            ("confirmed", "Confirmed"),
            ("false_positive", "False positive"),
        ),
        help_text="Your decision is immutable after submission.",
    )
    note = forms.CharField(
        required=False,
        max_length=2_000,
        widget=forms.Textarea(attrs={"rows": 5}),
        help_text=(
            "Record concise evidence-based reasoning. Do not include credentials "
            "or secrets."
        ),
    )
    governance_secret = forms.CharField(
        strip=False,
        widget=_SECRET_WIDGET,
        help_text=(
            "Used only to authenticate this governed decision; it is not stored "
            "by the web app."
        ),
    )


class GovernedAdjudicationForm(forms.Form):
    outcome = forms.ChoiceField(
        choices=(
            ("confirmed", "Confirmed"),
            ("false_positive", "False positive"),
        )
    )
    rationale = forms.CharField(
        min_length=8,
        max_length=2_000,
        widget=forms.Textarea(attrs={"rows": 6}),
        help_text="Explain how the evidence resolves the disagreement.",
    )
    governance_secret = forms.CharField(
        strip=False,
        widget=_SECRET_WIDGET,
        help_text=(
            "Used only to authenticate this adjudication; it is not stored by "
            "the web app."
        ),
    )
