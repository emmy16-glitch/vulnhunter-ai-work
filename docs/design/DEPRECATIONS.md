# Retired UI Guidance

This file records product-design guidance that is no longer authoritative. It exists so agents do not revive old concepts from historical documents, screenshots, tests or implementation leftovers.

The replacement source of truth is `docs/design/VULNHUNTER_UI_CONTRACT.md`.

## Retired visual direction

The following guidance is retired:

- a default all-dark or “dark security-operations” product surface;
- neon/cyberpunk styling;
- generic blue-and-white SaaS styling;
- soft floating-card shadows and large rounded cards as the default system;
- page-specific colours, radii, spacing or shadow systems;
- dense KPI/dashboard walls as the primary workspace.

The approved direction is the locked cream dotted canvas, dusty-pink accents, compact dark task/chat sidebar, near-black technical typography/borders, square geometry and hard zero-blur offset shadows.

## Retired information architecture

The following primary-navigation models are retired:

- `Overview → Collection → Analysis → Independent Review → Governance → Intelligence → Assurance` as the everyday user journey;
- the campaign control room as the centre of the product;
- every backend subsystem receiving equal permanent sidebar prominence;
- a generic “security operations dashboard” as the default landing/working model;
- mobile being treated as a separate bottom-tab dashboard product.

Campaigns, releases, datasets, analysis services, audit, reports, review/adjudication and other governed capabilities remain supported. They are progressively disclosed specialist/deep views of the same assessment/workspace state.

## Retired reference-derived concepts

Do not implement these merely because they appear in generated/reference screenshots:

- MonkeyCode or Threxa branding;
- `Projects` navigation copied from MonkeyCode;
- `Basic`, `Pro` or other reference-product account tiers;
- fictional model selectors such as `deepseek-v4-flash`, `gpt-4.1` or `vulnhunter-v1` unless a repository-backed product decision explicitly adds such a control;
- GitHub SSO or other unsupported sign-in methods;
- a generic operator `Pause` button;
- Share controls, layouts or other screenshot actions that are not repository-backed;
- DataHub-specific product language unless it is actually part of a VulnHunter workflow;
- browser-created operational percentages or success states.

## Historical documents and tests

A historical document may remain in the repository because it contains useful implementation history, security rationale, acceptance evidence or architecture detail. Where its visual/navigation wording conflicts with the locked UI contract, the locked UI contract wins.

Existing runtime code or tests may still encode the pre-redesign interface until the implementation programme reaches that slice. Their presence documents current implementation, not the approved future UI. Do not treat an old CSS token assertion or old navigation-label assertion as permission to revert the design contract.

## Deletion rule

Do not delete useful security, audit, worker, evidence, review or historical documentation merely because its UI examples are old. Remove or rewrite only guidance that is actively misleading, duplicated as a competing authority, or unsafe to follow without context.
