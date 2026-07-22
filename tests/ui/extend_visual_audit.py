#!/usr/bin/env python3
"""Expand the deterministic UI manifest to every stable HTML workspace."""

from __future__ import annotations

import json
import os
from pathlib import Path


def _identifier_from_path(path: str, prefix: str) -> str:
    if not path.startswith(prefix):
        raise ValueError(f"{path!r} does not start with {prefix!r}")
    return path.removeprefix(prefix).strip("/").split("/", 1)[0]


def main() -> int:
    manifest_path = Path(os.environ["VULNHUNTER_UI_MANIFEST"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pages = list(manifest["pages"])
    by_name = {str(page["name"]): page for page in pages}

    for page in pages:
        page["responsive"] = True

    run_id = _identifier_from_path(str(by_name["run-detail"]["path"]), "/scans/")
    campaign_id = _identifier_from_path(
        str(by_name["campaign-detail"]["path"]),
        "/campaigns/",
    )

    additions = [
        {"name": "system-status", "path": "/status/", "persona": "admin"},
        {
            "name": "authorizations",
            "path": "/authorizations/",
            "persona": "admin",
        },
        {"name": "review-queue", "path": "/reviews/", "persona": "reviewer"},
        {
            "name": "adjudication-queue",
            "path": "/adjudications/",
            "persona": "adjudicator",
        },
        {
            "name": "release-detail",
            "path": f"/releases/{campaign_id}/",
            "persona": "admin",
        },
        {
            "name": "dataset-detail",
            "path": f"/datasets/{campaign_id}/",
            "persona": "admin",
        },
        {
            "name": "model-graph-context",
            "path": "/models/graph-context/",
            "persona": "admin",
        },
        {
            "name": "model-advisory-analysis",
            "path": "/models/advisory-analysis/",
            "persona": "admin",
        },
        {
            "name": "model-deterministic-verification",
            "path": "/models/deterministic-verification/",
            "persona": "admin",
        },
        {"name": "governance", "path": "/governance/", "persona": "admin"},
        {
            "name": "campaign-readiness",
            "path": f"/readiness/{campaign_id}/",
            "persona": "admin",
        },
        {"name": "roles", "path": "/roles/", "persona": "admin"},
        {
            "name": "role-detail",
            "path": "/roles/orchestrator/",
            "persona": "admin",
        },
        {"name": "skills", "path": "/skills/", "persona": "admin"},
        {
            "name": "skill-detail",
            "path": "/skills/bounded-task-routing/",
            "persona": "admin",
        },
        {
            "name": "security-tools",
            "path": "/security-tools/",
            "persona": "admin",
        },
        {
            "name": "advanced-assessment",
            "path": "/advanced-assessment/",
            "persona": "admin",
        },
        {
            "name": "pilot-plans",
            "path": "/pilot/plans/",
            "persona": "admin",
        },
        {
            "name": "active-validation-create",
            "path": f"/scans/{run_id}/active-validation/new/",
            "persona": "admin",
        },
    ]

    for page in additions:
        page["responsive"] = True
        if page["name"] not in by_name:
            pages.append(page)
            by_name[page["name"]] = page

    manifest["pages"] = pages
    manifest["coverage"] = {
        "authenticated_html_pages": len(pages),
        "viewports_per_page": 6,
        "checks": [
            "HTTP and Django error state",
            "desktop, tablet, and mobile responsiveness",
            "horizontal and vertical overflow",
            "reachable final content and working scroll paths",
            "stable desktop scrollbar",
            "duplicate identifiers and unnamed controls",
            "placeholder links and unwired buttons",
            "POST form CSRF protection",
            "visible internal-link resolution",
            "search dialog and mobile navigation interactions",
            "static assets, console errors, and page errors",
        ],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
