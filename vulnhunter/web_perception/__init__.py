"""Passive browser perception and application-surface graph contracts."""

from vulnhunter.web_perception.activation import (
    WebPerceptionActivationConfig,
    WebPerceptionActivationError,
    build_web_perception_backend_from_environment,
)
from vulnhunter.web_perception.backend import (
    OpenSandboxWebPerceptionBackend,
    PlaywrightOpenSandboxRuntimeSpec,
)
from vulnhunter.web_perception.graph import build_surface_graph
from vulnhunter.web_perception.models import (
    ApplicationSurfaceGraph,
    BrowserPerceptionEvidence,
    BrowserPerceptionPolicy,
    PerceivedForm,
    PerceivedFormField,
    PerceivedNetworkRequest,
    PerceivedPage,
    SurfaceEdge,
    SurfaceEdgeKind,
    SurfaceNode,
    SurfaceNodeKind,
    WebPerceptionPlan,
    WebPerceptionResult,
)
from vulnhunter.web_perception.service import run_authorized_web_perception

__all__ = [
    "ApplicationSurfaceGraph",
    "BrowserPerceptionEvidence",
    "BrowserPerceptionPolicy",
    "OpenSandboxWebPerceptionBackend",
    "PerceivedForm",
    "PerceivedFormField",
    "PerceivedNetworkRequest",
    "PerceivedPage",
    "PlaywrightOpenSandboxRuntimeSpec",
    "SurfaceEdge",
    "SurfaceEdgeKind",
    "SurfaceNode",
    "SurfaceNodeKind",
    "WebPerceptionActivationConfig",
    "WebPerceptionActivationError",
    "WebPerceptionPlan",
    "WebPerceptionResult",
    "build_surface_graph",
    "build_web_perception_backend_from_environment",
    "run_authorized_web_perception",
]
