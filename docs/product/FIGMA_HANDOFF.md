# Figma Handoff

The installed Figma integrations are useful at the design stage, but they do not
become product runtime connectors. ChatGPT's Figma integration can create and refine
the editable design file from `config/product_interface/figma_handoff.json`. Codex's
Figma integration should be used later to compare implemented screens and component
behavior against the approved design system.

## File organization

Use the ten numbered Figma pages declared in the handoff specification. Build
foundations and reusable component sets before full screens. All screens use Auto
Layout, named variables, semantic layers, and component variants.

## Visual direction

Use a restrained dark security-operations theme with clear hierarchy, generous
spacing, readable evidence, and status semantics. Avoid neon overload, gratuitous
terminal styling, oversized charts without operational meaning, and generic admin
template layouts.

## Approval boundary

Figma represents approved interaction and visual behavior. It does not define
backend permissions, release eligibility, scan scope, or review independence.
