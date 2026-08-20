# VulnHunter Flutter/Dart client

This directory contains the first native client foundation. The Django/Python control plane remains authoritative for identity, roles, authorization, assessment plans, approvals, worker activation, evidence, findings, and dynamic-analysis gates. The app requests and renders those projections; it never calls scanner workers, emulators, Frida, MobSF, databases, SSH, or arbitrary commands directly.

`AuthSession` stores only short-lived access and revocation-capable refresh credentials through `flutter_secure_storage`. The current repository API slice exposes browser-session endpoints, so the native login/token exchange is intentionally an explicit integration boundary rather than a fabricated endpoint. A build without an established native session shows a truthful sign-in-required state.

Assessment realtime first reads persisted events after the last sequence, obtains a short-lived assessment-bound ticket, and connects to `ws/api/v1/assessments/{id}/events/`. Reconnects repeat the cursor and merge events by sequence. The upload client uses a configurable server endpoint, `Content-Range` chunks, acknowledged offsets, SHA-256 metadata, and server-side finalization. An APK upload does not imply static or dynamic execution; any dynamic work remains a backend approval- and readiness-gated state.

Run `flutter pub get`, `dart format lib test`, `dart analyze`, and `flutter test` when the Flutter SDK is available. URLs are supplied with `--dart-define`; no access token or provider/worker secret is compiled into the bundle.
