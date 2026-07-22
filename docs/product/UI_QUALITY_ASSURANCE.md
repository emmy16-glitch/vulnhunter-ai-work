# VulnHunter UI quality assurance

VulnHunter treats the browser interface as a governed product surface, not a decorative shell. A page is not considered ready merely because its URL resolves or a template compiles.

## Required pull-request gates

The repository quality workflow validates the web product at three levels:

1. **Static and application correctness**
   - Ruff lint and canonical formatting
   - Python compilation
   - scanner compatibility validation
   - the complete pytest suite
   - strict repository audit

2. **Backend-connected browser behaviour**
   - deterministic local-only campaign, assessment, finding, approval, review and adjudication records are seeded
   - authenticated administrator, reviewer and adjudicator personas exercise their real permission boundaries
   - the Django server is opened in Chromium with no external security action or public target

3. **Responsive visual evidence**
   - full-page screenshots are captured at reference desktop, common desktop, tablet and mobile widths
   - the audit fails on HTTP errors, Django error pages, console exceptions, failed static assets, body-level horizontal overflow, duplicate IDs, unnamed controls, missing sidebar selection or broken mobile navigation
   - screenshots, the server log and a machine-readable validation report are retained as workflow artifacts

## Activation policy

An interface element may report that a capability is gated, but it must not pretend that an unavailable backend action succeeded. Scanner enqueue, active validation, repository graph generation, remote advisory routing and mobile subprocess execution require their explicit reviewed configuration and local prerequisites.

The Settings surface reports those activation gates truthfully. It does not expose secrets and does not provide decorative toggles that bypass server-side policy.

## Report exports

Pilot-plan HTML and JSON downloads use the existing protected-data-safe `ReportExporter`. Other formats remain unavailable until their required finding, evidence or attack-path context exists. Rendering a report never publishes a finding or changes release state.

## Manual review

A green browser audit establishes that the rendered pages are operational, responsive and free from the automated defect classes above. Before a major visual redesign is merged, reviewers should still inspect the uploaded screenshots for hierarchy, density, readability and consistency with the approved dark security-console direction.
