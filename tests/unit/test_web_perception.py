from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.service import issue_authorization
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.scope import validate_target
from vulnhunter.security_tools.opensandbox_supply_chain import ApprovedWorkerRelease
from vulnhunter.web_perception.backend import (
    OpenSandboxWebPerceptionBackend,
    PlaywrightOpenSandboxRuntimeSpec,
)
from vulnhunter.web_perception.errors import WebPerceptionError
from vulnhunter.web_perception.graph import build_surface_graph
from vulnhunter.web_perception.models import (
    BrowserPerceptionEvidence,
    BrowserPerceptionPolicy,
    PerceivedForm,
    PerceivedFormField,
    PerceivedNetworkRequest,
    PerceivedPage,
)
from vulnhunter.web_perception.service import run_authorized_web_perception

_IMAGE = "localhost:5000/vulnhunter-playwright@sha256:" + "a" * 64


def _release() -> ApprovedWorkerRelease:
    return ApprovedWorkerRelease(
        worker_id="playwright",
        release_id="playwright-ci-release",
        image=_IMAGE,
        sbom_sha256="b" * 64,
        provenance_sha256="c" * 64,
        source_commit="d" * 40,
        status="approved",
    )


def _page(url: str, *, depth: int = 0) -> PerceivedPage:
    form = PerceivedForm(
        form_sha256="1" * 64,
        method="POST",
        action_url=url.rstrip("/") + "/submit",
        fields=(
            PerceivedFormField(name="username", input_type="text", required=True),
            PerceivedFormField(name="password", input_type="password", required=True),
        ),
    )
    return PerceivedPage(
        url=url,
        depth=depth,
        status_code=200,
        dom_structure_sha256="2" * 64,
        links=(url.rstrip("/") + "/profile",),
        scripts=(url.rstrip("/") + "/static/app.js",),
        forms=(form,),
        requests=(
            PerceivedNetworkRequest(
                method="GET",
                url=url.rstrip("/") + "/api/info",
                resource_type="fetch",
                status_code=200,
            ),
        ),
    )


def test_surface_graph_is_deterministic_and_structure_only() -> None:
    page = _page("http://10.1.2.3:8012/app/")
    graph_a = build_surface_graph(page.url, (page,))
    graph_b = build_surface_graph(page.url, (page,))

    assert graph_a == graph_b
    assert graph_a.graph_sha256
    assert {node.kind.value for node in graph_a.nodes} >= {
        "page",
        "endpoint",
        "form",
        "script",
    }
    serialized = graph_a.model_dump_json()
    assert "password" not in serialized
    assert "secret-value" not in serialized


def test_form_field_contract_rejects_values() -> None:
    with pytest.raises(ValidationError):
        PerceivedFormField.model_validate(
            {
                "name": "password",
                "input_type": "password",
                "required": True,
                "value": "secret-value",
            }
        )


def test_page_contract_rejects_page_text() -> None:
    with pytest.raises(ValidationError):
        PerceivedPage.model_validate(
            {
                "url": "http://10.1.2.3:8012/app/",
                "depth": 0,
                "status_code": 200,
                "title": "target-controlled page text",
                "dom_structure_sha256": "2" * 64,
            }
        )


class _FakeSdk:
    def __init__(self, evidence: BrowserPerceptionEvidence) -> None:
        self.evidence = evidence
        self.allowed_ip: str | None = None
        self.created = False
        self.destroyed = False
        self.plan_payload: dict[str, object] | None = None

    def create(self, *, runtime, allowed_ip, lifetime_seconds, metadata):
        del runtime, lifetime_seconds, metadata
        self.created = True
        self.allowed_ip = allowed_ip
        return object()

    def make_directory(self, sandbox, path, *, mode):
        del sandbox, path, mode

    def write_file(self, sandbox, path, data, *, mode):
        del sandbox, mode
        if path.endswith("plan.json"):
            self.plan_payload = json.loads(str(data))

    def run_worker(self, sandbox, *, runtime, timeout_seconds):
        del sandbox, runtime, timeout_seconds
        return 0

    def read_bytes(self, sandbox, path):
        del sandbox, path
        return self.evidence.model_dump_json().encode()

    def destroy(self, sandbox):
        del sandbox
        self.destroyed = True


def _backend(fake: _FakeSdk, *, resolver=lambda _host: ("10.1.2.3",)):
    return OpenSandboxWebPerceptionBackend(
        runtime=PlaywrightOpenSandboxRuntimeSpec(image=_IMAGE),
        release=_release(),
        release_registry_sha256="e" * 64,
        release_key_id="sha256:" + "f" * 64,
        resolver=resolver,
        sdk=fake,
    )


def test_backend_binds_exact_ip_sanitizes_evidence_and_destroys() -> None:
    target = validate_target(
        "http://perception.lab.test:8012/app/",
        resolver=lambda _host: ("10.1.2.3",),
    )
    raw_page = _page("http://perception.lab.test:8012/app/").model_copy(
        update={
            "requests": (
                PerceivedNetworkRequest(
                    method="GET",
                    url="http://perception.lab.test:8012/app/api?token=secret-value",
                    resource_type="fetch",
                    status_code=200,
                ),
            ),
        }
    )
    fake = _FakeSdk(
        BrowserPerceptionEvidence(
            pages=(raw_page,),
            allowed_requests=2,
            blocked_external_requests=1,
            blocked_mutating_requests=1,
            blocked_websockets=1,
        )
    )
    result = _backend(fake).execute(
        target,
        authorization_id="auth-0123456789abcdef0123",
        policy=BrowserPerceptionPolicy(maximum_pages=2, maximum_requests=20),
    )

    assert fake.created is True
    assert fake.destroyed is True
    assert fake.allowed_ip == "10.1.2.3"
    assert fake.plan_payload is not None
    assert fake.plan_payload["approved_ip"] == "10.1.2.3"
    assert "secret-value" not in result.model_dump_json()
    assert result.graph.graph_sha256
    assert result.plan_sha256
    assert result.evidence_sha256


def test_backend_refuses_dns_change_before_sandbox_creation() -> None:
    target = validate_target(
        "http://perception.lab.test:8012/app/",
        resolver=lambda _host: ("10.1.2.3",),
    )
    fake = _FakeSdk(
        BrowserPerceptionEvidence(
            pages=(_page("http://perception.lab.test:8012/app/"),),
            allowed_requests=1,
            blocked_external_requests=0,
            blocked_mutating_requests=0,
            blocked_websockets=0,
        )
    )
    backend = _backend(fake, resolver=lambda _host: ("10.1.2.4",))

    with pytest.raises(WebPerceptionError, match="DNS changed"):
        backend.execute(
            target,
            authorization_id="auth-0123456789abcdef0123",
            policy=BrowserPerceptionPolicy(),
        )

    assert fake.created is False
    assert fake.destroyed is False


def test_authorized_entry_point_validates_before_backend_execution(tmp_path) -> None:
    target = validate_target(
        "http://perception.lab.test:8012/app/",
        resolver=lambda _host: ("10.1.2.3",),
    )
    store = AuthorizationStore.from_path(tmp_path / "authorizations.db")
    store.initialize()
    record = issue_authorization(
        store,
        target,
        owner="test-owner",
        approved_by="test-approver",
        purpose="private browser perception acceptance",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        limits=AuthorizationLimits(
            maximum_pages=3,
            maximum_depth=2,
            maximum_requests=25,
            minimum_request_delay_seconds=0,
        ),
    )
    fake = _FakeSdk(
        BrowserPerceptionEvidence(
            pages=(_page("http://perception.lab.test:8012/app/"),),
            allowed_requests=1,
            blocked_external_requests=0,
            blocked_mutating_requests=0,
            blocked_websockets=0,
        )
    )
    backend = _backend(fake)

    result = run_authorized_web_perception(
        target,
        authorization_store=store,
        authorization_id=record.authorization_id,
        policy=BrowserPerceptionPolicy(
            maximum_pages=2,
            maximum_depth=1,
            maximum_requests=10,
            minimum_request_delay_seconds=0,
        ),
        backend=backend,
    )

    assert result.graph.graph_sha256
    assert fake.created is True
    event_types = [event.event_type for event in store.list_events(record.authorization_id)]
    assert event_types[:3] == ["scan_completed", "scan_started", "validated"]


def test_authorized_entry_point_rejects_budget_expansion_before_sandbox(tmp_path) -> None:
    target = validate_target(
        "http://perception.lab.test:8012/app/",
        resolver=lambda _host: ("10.1.2.3",),
    )
    store = AuthorizationStore.from_path(tmp_path / "authorizations.db")
    store.initialize()
    record = issue_authorization(
        store,
        target,
        owner="test-owner",
        approved_by="test-approver",
        purpose="private browser perception acceptance",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        limits=AuthorizationLimits(
            maximum_pages=1,
            maximum_depth=0,
            maximum_requests=5,
            minimum_request_delay_seconds=0.2,
        ),
    )
    fake = _FakeSdk(
        BrowserPerceptionEvidence(
            pages=(_page("http://perception.lab.test:8012/app/"),),
            allowed_requests=1,
            blocked_external_requests=0,
            blocked_mutating_requests=0,
            blocked_websockets=0,
        )
    )

    with pytest.raises(Exception, match="page limit exceeds"):
        run_authorized_web_perception(
            target,
            authorization_store=store,
            authorization_id=record.authorization_id,
            policy=BrowserPerceptionPolicy(
                maximum_pages=2,
                maximum_depth=0,
                maximum_requests=5,
                minimum_request_delay_seconds=0.2,
            ),
            backend=_backend(fake),
        )

    assert fake.created is False


def test_activation_is_disabled_by_default() -> None:
    from vulnhunter.web_perception.activation import WebPerceptionActivationConfig

    assert WebPerceptionActivationConfig.from_environment({}).build_backend() is None


def test_activation_requires_signed_release_files() -> None:
    from vulnhunter.web_perception.activation import (
        WebPerceptionActivationConfig,
        WebPerceptionActivationError,
    )

    with pytest.raises(WebPerceptionActivationError, match="signed Playwright worker"):
        WebPerceptionActivationConfig.from_environment(
            {
                "VULNHUNTER_WEB_PERCEPTION_ENABLED": "true",
                "VULNHUNTER_WEB_PERCEPTION_PLAYWRIGHT_IMAGE": _IMAGE,
                "VULNHUNTER_OPENSANDBOX_DOMAIN": "localhost:8080",
                "VULNHUNTER_OPENSANDBOX_PROTOCOL": "http",
            }
        )
