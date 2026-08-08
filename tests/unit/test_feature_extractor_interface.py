import pytest

from vulnhunter.ml.feature_extractors import (
    default_feature_extractor,
    get_feature_extractor,
    registered_feature_extractors,
)
from vulnhunter.ml.models import FeatureSchema, TrainingExample


def _example(*, category: str = "headers", title: str = "Missing security header") -> TrainingExample:
    return TrainingExample(
        observation_id=1,
        scan_id=1,
        category=category,
        severity="low",
        title=title,
        description="A redacted passive observation for human review.",
        url="https://example.invalid/admin/docs",
        evidence={
            "status_code": 200,
            "missing_headers": ["content-security-policy"],
            "detected_indicators": [],
        },
        fingerprint="a" * 64,
        label="confirmed",
    )


def test_baseline_extractor_is_versioned_deterministic_and_offline() -> None:
    descriptor = default_feature_extractor().descriptor

    assert descriptor.extractor_id == "deterministic-observation"
    assert descriptor.version == "2"
    assert descriptor.input_schema == "observation-input-v1"
    assert descriptor.redaction_policy == "redacted-observation-v1"
    assert descriptor.deterministic is True
    assert descriptor.network_access is False
    assert descriptor.allowed_tasks == ("review_priority",)
    assert registered_feature_extractors() == (descriptor,)


def test_extraction_binds_exact_metadata_to_every_emitted_feature() -> None:
    extractor = default_feature_extractor()
    example = _example()
    schema = extractor.build_schema((example,), maximum_tokens=8)

    result = extractor.extract(example, schema)

    assert result.extractor == extractor.descriptor
    assert tuple(item.name for item in result.feature_metadata) == schema.feature_names
    assert len(result.vector) == len(schema.feature_names)
    assert all(item.allowed_tasks == ("review_priority",) for item in result.feature_metadata)
    assert all(item.privacy_classification for item in result.feature_metadata)
    assert all(item.leakage_risk for item in result.feature_metadata)


def test_dynamic_category_and_text_features_declare_leakage_risk() -> None:
    extractor = default_feature_extractor()
    example = _example(category="debug", title="Debug traceback exposed")
    schema = extractor.build_schema((example,), maximum_tokens=16)
    metadata = {item.name: item for item in extractor.metadata_for_schema(schema)}

    category = metadata["category:debug"]
    assert category.source_field == "category"
    assert "no-category" in category.leakage_risk

    token = next(item for name, item in metadata.items() if name.startswith("token:"))
    assert token.source_field == "title+description"
    assert token.privacy_classification == "redacted_text"
    assert "no-text" in token.leakage_risk


def test_unknown_extractor_identity_fails_closed() -> None:
    with pytest.raises(ValueError, match="Unknown or ambiguous"):
        get_feature_extractor("unregistered-transformer")

    with pytest.raises(ValueError, match="Unknown or ambiguous"):
        get_feature_extractor("deterministic-observation", version="999")


def test_unknown_fixed_feature_fails_before_vectorization() -> None:
    extractor = default_feature_extractor()
    schema = FeatureSchema(
        schema_version=2,
        categories=("headers",),
        tokens=(),
        fixed_features=("evidence:not_registered",),
    )

    with pytest.raises(ValueError, match="Unknown registered feature"):
        extractor.extract(_example(), schema)


def test_schema_version_mismatch_fails_closed() -> None:
    extractor = default_feature_extractor()
    schema = FeatureSchema(
        schema_version=1,
        categories=("headers",),
        tokens=(),
        fixed_features=("url:https",),
    )

    with pytest.raises(ValueError, match="not compatible"):
        extractor.metadata_for_schema(schema)
