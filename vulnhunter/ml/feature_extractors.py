"""Versioned feature-extractor contracts for governed ML tasks."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnhunter.ml.features import build_feature_schema, vectorize
from vulnhunter.ml.models import FeatureSchema, ObservationInput, TrainingExample

FeaturePrivacy = Literal["redacted_metadata", "redacted_text", "derived_numeric"]
FeatureStability = Literal["stable", "vocabulary_bound", "source_dependent"]
FeatureTask = Literal["review_priority"]

_BASELINE_EXTRACTOR_ID = "deterministic-observation"
_BASELINE_EXTRACTOR_VERSION = "2"
_BASELINE_INPUT_SCHEMA = "observation-input-v1"
_BASELINE_REDACTION_POLICY = "redacted-observation-v1"


class FeatureMetadata(BaseModel):
    """Registered provenance and safety metadata for one emitted feature."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    source_field: str = Field(min_length=1, max_length=200)
    transformation: str = Field(min_length=1, max_length=500)
    privacy_classification: FeaturePrivacy
    allowed_tasks: tuple[FeatureTask, ...] = ("review_priority",)
    missing_value_behavior: str = Field(min_length=1, max_length=300)
    expected_range: str = Field(min_length=1, max_length=300)
    leakage_risk: str = Field(min_length=1, max_length=500)
    stability: FeatureStability
    deprecated: bool = False


class FeatureExtractorDescriptor(BaseModel):
    """Immutable identity and capability declaration for one extractor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    extractor_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,79}$")
    version: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,39}$")
    input_schema: str = Field(min_length=1, max_length=100)
    redaction_policy: str = Field(min_length=1, max_length=100)
    deterministic: bool
    network_access: Literal[False] = False
    allowed_tasks: tuple[FeatureTask, ...] = ("review_priority",)
    output_schema_version: int = Field(ge=1)


class FeatureExtraction(BaseModel):
    """One validated vector plus exact extractor and feature provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    extractor: FeatureExtractorDescriptor
    feature_schema: FeatureSchema
    feature_metadata: tuple[FeatureMetadata, ...]
    vector: tuple[float, ...]

    @model_validator(mode="after")
    def validate_dimensions(self) -> FeatureExtraction:
        names = self.feature_schema.feature_names
        metadata_names = tuple(item.name for item in self.feature_metadata)
        if metadata_names != names:
            raise ValueError("feature metadata must exactly match schema feature order")
        if len(self.vector) != len(names):
            raise ValueError("feature vector dimensions must match the feature schema")
        return self


@runtime_checkable
class FeatureExtractor(Protocol):
    """Interface implemented by deterministic or future local model extractors."""

    @property
    def descriptor(self) -> FeatureExtractorDescriptor: ...

    def build_schema(
        self,
        examples: Sequence[TrainingExample],
        *,
        maximum_tokens: int = 128,
        minimum_document_frequency: int = 1,
    ) -> FeatureSchema: ...

    def metadata_for_schema(self, schema: FeatureSchema) -> tuple[FeatureMetadata, ...]: ...

    def extract(self, example: ObservationInput, schema: FeatureSchema) -> FeatureExtraction: ...


_FIXED_METADATA: Mapping[str, FeatureMetadata] = {
    name: FeatureMetadata(
        name=name,
        source_field=("url" if name.startswith("url:") else "evidence"),
        transformation="Deterministic bounded numeric or boolean transformation defined by features.py.",
        privacy_classification="derived_numeric",
        missing_value_behavior="Missing source values produce the documented zero/default representation.",
        expected_range=("non-negative bounded count or binary indicator"),
        leakage_risk=(
            "May encode detector or evidence-source behaviour; must be covered by leakage ablations."
        ),
        stability="stable",
    )
    for name in build_feature_schema(
        (
            TrainingExample(
                observation_id=1,
                scan_id=1,
                category="baseline",
                severity="info",
                title="baseline observation",
                description="baseline observation description",
                url="https://example.invalid/",
                evidence={},
                fingerprint="0" * 64,
                label="confirmed",
            ),
        ),
        maximum_tokens=0,
    ).fixed_features
}


class DeterministicObservationFeatureExtractor:
    """Adapter around the existing privacy-conscious deterministic baseline."""

    descriptor = FeatureExtractorDescriptor(
        extractor_id=_BASELINE_EXTRACTOR_ID,
        version=_BASELINE_EXTRACTOR_VERSION,
        input_schema=_BASELINE_INPUT_SCHEMA,
        redaction_policy=_BASELINE_REDACTION_POLICY,
        deterministic=True,
        output_schema_version=2,
    )

    def build_schema(
        self,
        examples: Sequence[TrainingExample],
        *,
        maximum_tokens: int = 128,
        minimum_document_frequency: int = 1,
    ) -> FeatureSchema:
        return build_feature_schema(
            examples,
            maximum_tokens=maximum_tokens,
            minimum_document_frequency=minimum_document_frequency,
        )

    def metadata_for_schema(self, schema: FeatureSchema) -> tuple[FeatureMetadata, ...]:
        if schema.schema_version != self.descriptor.output_schema_version:
            raise ValueError("feature schema is not compatible with this extractor version")

        metadata: list[FeatureMetadata] = []
        for name in schema.feature_names:
            if name.startswith("severity:"):
                metadata.append(
                    FeatureMetadata(
                        name=name,
                        source_field="severity",
                        transformation="Exact one-hot severity category.",
                        privacy_classification="redacted_metadata",
                        missing_value_behavior="Severity is required by ObservationInput.",
                        expected_range="0 or 1",
                        leakage_risk="May reproduce scanner-assigned severity; evaluate no-severity ablation.",
                        stability="stable",
                    )
                )
            elif name.startswith("category:"):
                metadata.append(
                    FeatureMetadata(
                        name=name,
                        source_field="category",
                        transformation="Training-vocabulary one-hot category.",
                        privacy_classification="redacted_metadata",
                        missing_value_behavior="Unknown categories emit zero for every trained category.",
                        expected_range="0 or 1",
                        leakage_risk="May reproduce detector category; evaluate no-category and leave-category-out ablations.",
                        stability="vocabulary_bound",
                    )
                )
            elif name.startswith("token:"):
                metadata.append(
                    FeatureMetadata(
                        name=name,
                        source_field="title+description",
                        transformation="Presence of one bounded token selected from redacted training text.",
                        privacy_classification="redacted_text",
                        missing_value_behavior="Absent or unseen token emits zero.",
                        expected_range="0 or 1",
                        leakage_risk="Detector-generated wording may leak labels; evaluate no-text and no-detector-text ablations.",
                        stability="vocabulary_bound",
                    )
                )
            else:
                registered = _FIXED_METADATA.get(name)
                if registered is None:
                    raise ValueError(f"Unknown registered feature: {name}")
                metadata.append(registered)
        return tuple(metadata)

    def extract(self, example: ObservationInput, schema: FeatureSchema) -> FeatureExtraction:
        metadata = self.metadata_for_schema(schema)
        values = vectorize(example, schema)
        return FeatureExtraction(
            extractor=self.descriptor,
            feature_schema=schema,
            feature_metadata=metadata,
            vector=values,
        )


_BASELINE_EXTRACTOR = DeterministicObservationFeatureExtractor()
_EXTRACTORS: tuple[FeatureExtractor, ...] = (_BASELINE_EXTRACTOR,)


def registered_feature_extractors() -> tuple[FeatureExtractorDescriptor, ...]:
    """Return the immutable registry of currently implemented extractors."""

    return tuple(extractor.descriptor for extractor in _EXTRACTORS)


def get_feature_extractor(extractor_id: str, version: str | None = None) -> FeatureExtractor:
    """Resolve exactly one known extractor or fail closed."""

    matches = tuple(
        extractor
        for extractor in _EXTRACTORS
        if extractor.descriptor.extractor_id == extractor_id
        and (version is None or extractor.descriptor.version == version)
    )
    if len(matches) != 1:
        raise ValueError("Unknown or ambiguous feature extractor identity")
    return matches[0]


def default_feature_extractor() -> FeatureExtractor:
    """Return the explicit current deterministic baseline extractor."""

    return _BASELINE_EXTRACTOR
