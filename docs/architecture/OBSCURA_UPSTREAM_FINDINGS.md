# Obscura upstream findings (research notes)

Source inspected: https://github.com/h4ckf0r0day/obscura

The current upstream repository presents Obscura as a Rust headless browser for AI agents and web scraping. The repository page showed the latest visible commit `13198fd` on `main` and 13 tags. The README documents an MCP server with stdio as the default transport, started with `obscura mcp`. HTTP MCP is also available with `obscura mcp --http --port 8080`, but VulnHunter should not expose that listener as its initial integration transport.

The documented MCP browser tools are: `browser_navigate`, `browser_snapshot`, `browser_screenshot`, `browser_pdf`, `browser_click`, `browser_fill`, `browser_type`, `browser_press_key`, `browser_select_option`, `browser_evaluate`, `browser_wait_for`, `browser_network_requests`, `browser_console_messages`, and `browser_close`. The README explicitly says the MCP server provides still-image and PDF output and that CDP is required for streaming `Page.startScreencast`.

The initial design implication is to use a local worker-owned stdio process and a narrow adapter that exposes only the VulnHunter-approved subset. Obscura remains a runtime implementation, not an authorization, evidence, Source Hunt, finding, or validation authority. `browser_evaluate`, PDF, and close/state-reset operations require special policy treatment and should not be exposed through a general AI action list by default.

## Release and licensing findings

The upstream tags endpoint currently lists `v0.2.0` at commit `97124edeb2ea610615e78f43e097454e3b221f6b`, followed by `v0.1.11` and older tags. The release API exposes `v0.2.0` assets for Linux x86_64, including `obscura-x86_64-linux.tar.gz` with upstream-provided SHA-256 digest `d601f4f542319c3b9fa8dca9f5ccfc134a2ca001648da528db5f03c9e6c2599b`, plus `-stealth`, `-no-render`, and `-no-render-stealth` variants. The plain Linux archive is the appropriate first candidate for screenshots/rendering; no-render is insufficient for screenshot evidence.

The README documents release downloads, no Chrome/Node dependency, an archive containing both `obscura` and `obscura-worker`, and Linux builds targeting Ubuntu 22.04/glibc 2.35+. It also documents source builds requiring Rust and potentially V8/BoringSSL build dependencies. VulnHunter should prefer the pinned release asset over a source build and should verify the downloaded archive and extracted executable against a locally recorded digest before enabling the adapter.

The upstream repository exposes Apache License 2.0. VulnHunter must preserve the license and any upstream NOTICE/attribution requirements if it distributes or packages the runtime. The repository page also advertises stealth and proxy options; these are not implicitly allowed by VulnHunter policy and must not be enabled by a browser action unless an explicit policy contract authorizes them.
