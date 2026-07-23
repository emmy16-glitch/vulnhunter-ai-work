from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    content = target.read_text(encoding="utf-8")
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"Expected one match in {path}, found {count}: {old[:100]!r}")
    target.write_text(content.replace(old, new, 1), encoding="utf-8")


def replace_all(path: str, old: str, new: str, expected: int) -> None:
    target = ROOT / path
    content = target.read_text(encoding="utf-8")
    count = content.count(old)
    if count != expected:
        raise RuntimeError(f"Expected {expected} matches in {path}, found {count}: {old[:100]!r}")
    target.write_text(content.replace(old, new), encoding="utf-8")


# Public website targets remain opt-in. Existing callers stay private-lab only.
replace_once(
    "vulnhunter/scope/validator.py",
    "def _validate_ip_address(address_text: str) -> str:\n",
    "def _validate_ip_address(address_text: str, *, allow_public: bool = False) -> str:\n",
)
replace_once(
    "vulnhunter/scope/validator.py",
    "    if address.is_global:\n        raise ScopeValidationError(f\"Public Internet addresses are prohibited: {address}\")\n",
    "    if address.is_global:\n        if allow_public:\n            return str(address)\n        raise ScopeValidationError(f\"Public Internet addresses are prohibited: {address}\")\n",
)
replace_once(
    "vulnhunter/scope/validator.py",
    "def validate_target(\n    url: str,\n    *,\n    resolver: Resolver = system_resolver,\n) -> ApprovedTarget:\n",
    "def validate_target(\n    url: str,\n    *,\n    resolver: Resolver = system_resolver,\n    allow_public: bool = False,\n) -> ApprovedTarget:\n",
)
replace_once(
    "vulnhunter/scope/validator.py",
    "    approved_addresses = tuple(\n        sorted({_validate_ip_address(address) for address in resolved_addresses})\n    )\n",
    "    approved_addresses = tuple(\n        sorted(\n            {\n                _validate_ip_address(address, allow_public=allow_public)\n                for address in resolved_addresses\n            }\n        )\n    )\n",
)

# Teach the chat parser to accept pasted websites, explicit authorization, and evidence.
replace_once(
    "vulnhunter/web/conversation_service.py",
    "_PORT_PATTERN = re.compile(r\"\\bport\\s*[:#-]?\\s*([0-9]{1,5})\\b\", re.IGNORECASE)\n",
    "_PORT_PATTERN = re.compile(r\"\\bport\\s*[:#-]?\\s*([0-9]{1,5})\\b\", re.IGNORECASE)\n_EVIDENCE_PATTERN = re.compile(r\"\\bevidence\\s*[:=-]\\s*(.+)$\", re.IGNORECASE)\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "_CANCEL_WORDS = (\"cancel\", \"stop\", \"abort\")\n",
    "_CANCEL_WORDS = (\"cancel\", \"stop\", \"abort\")\n_AUTHORIZE_WORDS = (\n    \"authorize\",\n    \"authorise\",\n    \"i own this target\",\n    \"i control this target\",\n    \"i am authorized\",\n    \"i am authorised\",\n)\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "    profile: str | None\n    assistant_copy: str | None\n",
    "    profile: str | None\n    evidence_reference: str | None\n    assistant_copy: str | None\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "    match = _BARE_TARGET_PATTERN.search(text)\n    if match:\n        return canonical_target(match.group(0)) or None\n    return None\n",
    "    match = _BARE_TARGET_PATTERN.search(text)\n    if match:\n        return canonical_target(match.group(0)) or None\n    match = _BARE_HOSTNAME_PATTERN.search(text)\n    if match:\n        return canonical_target(match.group(0)) or None\n    return None\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "def _contains_term(text: str, term: str) -> bool:\n",
    "def extract_evidence_reference(text: str) -> str | None:\n    match = _EVIDENCE_PATTERN.search(text)\n    if not match:\n        return None\n    value = redact_text(\" \".join(match.group(1).split())).strip()[:2_000]\n    if not value or value.startswith(\"<\") or value.startswith(\"[\"):\n        return None\n    return value\n\n\ndef _contains_term(text: str, term: str) -> bool:\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "    lowered = \" \".join(text.casefold().split())\n    if any(_contains_term(lowered, word) for word in _CANCEL_WORDS):\n",
    "    lowered = \" \".join(text.casefold().split())\n    if any(_contains_term(lowered, word) for word in _AUTHORIZE_WORDS):\n        return \"authorize\"\n    if any(_contains_term(lowered, word) for word in _CANCEL_WORDS):\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "    return (\n        \"I can answer questions about this workspace or the active assessment. Ask for the target \"\n        \"link, current status, approval state, findings, evidence or the next safe step.\"\n    )\n",
    "    return (\n        \"Paste an http or https website link and I will identify its host, path and port, check \"\n        \"authorization, prepare the passive plan and explain each live step. You can also ask about \"\n        \"the current target, approval, findings, evidence or next action.\"\n    )\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "def _groq_advisory(\n    text: str,\n    *,\n    available_profiles: tuple[str, ...],\n) -> tuple[str | None, str]:\n",
    "def _groq_advisory(\n    text: str,\n    *,\n    available_profiles: tuple[str, ...],\n    conversation_context: tuple[tuple[str, str], ...] = (),\n) -> tuple[str | None, str]:\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "    sanitized = _sanitize_for_groq(text)\n    prompt = (\n",
    "    sanitized = _sanitize_for_groq(text)\n    sanitized_context = [\n        {\"role\": role, \"content\": _sanitize_for_groq(content)[:600]}\n        for role, content in conversation_context[-8:]\n        if role in {\"user\", \"assistant\"} and content.strip()\n    ]\n    prompt = (\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "        f\"Available profiles: {', '.join(available_profiles) or 'none'}. \"\n        f\"Sanitized user request: {sanitized}\"\n",
    "        f\"Available profiles: {', '.join(available_profiles) or 'none'}. \"\n        f\"Recent sanitized conversation: {json.dumps(sanitized_context, ensure_ascii=False)}. \"\n        f\"Sanitized user request: {sanitized}\"\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "def interpret_request(\n    text: str,\n    *,\n    available_profiles: tuple[str, ...],\n) -> InterpretedRequest:\n",
    "def interpret_request(\n    text: str,\n    *,\n    available_profiles: tuple[str, ...],\n    conversation_context: tuple[tuple[str, str], ...] = (),\n) -> InterpretedRequest:\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "    profile = extract_profile(text)\n    deterministic = deterministic_intent(text)\n",
    "    profile = extract_profile(text)\n    evidence_reference = extract_evidence_reference(text)\n    deterministic = deterministic_intent(text)\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "    advisory, advisory_detail = _groq_advisory(\n        text,\n        available_profiles=available_profiles,\n    )\n",
    "    advisory, advisory_detail = _groq_advisory(\n        text,\n        available_profiles=available_profiles,\n        conversation_context=conversation_context,\n    )\n",
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    "        profile=profile,\n        assistant_copy=assistant_copy,\n",
    "        profile=profile,\n        evidence_reference=evidence_reference,\n        assistant_copy=assistant_copy,\n",
)

helper = '''\"\"\"Explicit, short-lived authorization intake for pasted website targets.\"\"\"\n\nfrom __future__ import annotations\n\nimport ipaddress\nimport re\nfrom collections.abc import Iterable\nfrom dataclasses import dataclass\nfrom datetime import UTC, datetime, timedelta\nfrom pathlib import Path\n\nfrom django.conf import settings\n\nfrom vulnhunter.authorization.models import AuthorizationLimits\nfrom vulnhunter.authorization.service import issue_authorization\nfrom vulnhunter.authorization.store import AuthorizationStore\nfrom vulnhunter.exceptions import AuthorizationPolicyError, ScopeValidationError\nfrom vulnhunter.scope import validate_target\nfrom vulnhunter.scope.validator import Resolver, system_resolver\nfrom vulnhunter.security import redact_text\nfrom vulnhunter.web.assessment_workflow import (\n    AssessmentWorkflowError,\n    bind_nuclei_authorization,\n    load_nuclei_authorization,\n)\n\n\nclass ConversationalAuthorizationError(RuntimeError):\n    \"\"\"Raised when chat cannot safely create the requested authorization.\"\"\"\n\n\n@dataclass(frozen=True)\nclass PreparedConversationalAuthorization:\n    authorization_id: str\n    target: str\n    port: int\n    address_class: str\n    reused: bool\n\n\ndef _stable_identifier(value: str) -> str:\n    normalized = re.sub(r\"[^a-z0-9._-]+\", \"-\", value.strip().casefold()).strip(\"-._\")\n    if len(normalized) < 2:\n        normalized = \"vh-user\"\n    return normalized[:128]\n\n\ndef _address_class(addresses: Iterable[str]) -> str:\n    classes: set[str] = set()\n    for raw in addresses:\n        address = ipaddress.ip_address(raw)\n        if address.is_loopback:\n            raise ConversationalAuthorizationError(\n                \"Loopback targets cannot be handed to the isolated Nuclei worker.\"\n            )\n        if address.is_link_local or address.is_unspecified or address.is_multicast:\n            raise ConversationalAuthorizationError(\n                \"Link-local, unspecified and multicast targets are not permitted.\"\n            )\n        if address.is_private:\n            classes.add(\"private\")\n        elif address.is_global:\n            classes.add(\"public\")\n        else:\n            raise ConversationalAuthorizationError(\n                \"The target resolves to an unsupported special-use address.\"\n            )\n    if len(classes) != 1:\n        raise ConversationalAuthorizationError(\n            \"The target mixes public and private addresses, so authorization fails closed.\"\n        )\n    return next(iter(classes))\n\n\ndef prepare_conversational_authorization(\n    *,\n    target_url: str,\n    evidence_reference: str | None,\n    identity_id: str,\n    username: str,\n    authorization_store: AuthorizationStore | None = None,\n    resolver: Resolver = system_resolver,\n    now: datetime | None = None,\n) -> PreparedConversationalAuthorization:\n    \"\"\"Create or reuse an exact passive authorization for one pasted URL and port.\"\"\"\n\n    instant = (now or datetime.now(UTC)).astimezone(UTC)\n    try:\n        target = validate_target(target_url, resolver=resolver, allow_public=True)\n    except (OSError, ScopeValidationError, ValueError) as exc:\n        raise ConversationalAuthorizationError(str(exc)) from exc\n\n    address_class = _address_class(target.resolved_addresses)\n    evidence = redact_text(evidence_reference or \"\").strip()[:2_000]\n    if address_class == \"public\" and len(evidence) < 8:\n        raise ConversationalAuthorizationError(\n            \"This public website needs an authorization evidence reference. Send: \"\n            \"Authorize this target. Evidence: <contract, ticket, or bug-bounty scope reference>.\"\n        )\n    if not evidence:\n        evidence = \"Interactive confirmation for a self-controlled private target.\"\n\n    store = authorization_store or AuthorizationStore.from_path(\n        Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE)\n    )\n    store.initialize()\n    owner = identity_id.strip() or username.strip()\n    record = next(\n        (\n            item\n            for item in store.list(limit=250)\n            if item.status == \"active\"\n            and item.owner.casefold() in {identity_id.casefold(), username.casefold()}\n            and item.target_url == target.normalized_url\n            and instant < item.expires_at\n        ),\n        None,\n    )\n    reused = record is not None\n    if record is None:\n        try:\n            record = issue_authorization(\n                store,\n                target,\n                owner=owner,\n                approved_by=f\"{_stable_identifier(owner)}.interactive-confirmation\",\n                purpose=\"Governed passive website assessment requested in the chat workspace.\",\n                evidence_reference=evidence,\n                expires_at=instant + timedelta(hours=12),\n                limits=AuthorizationLimits(\n                    maximum_pages=2,\n                    maximum_depth=0,\n                    maximum_requests=10,\n                    minimum_request_delay_seconds=1,\n                ),\n                now=instant,\n            )\n        except (AuthorizationPolicyError, OSError, ValueError) as exc:\n            raise ConversationalAuthorizationError(str(exc)) from exc\n\n    principal = _stable_identifier(identity_id or username)\n    try:\n        _, engagement = load_nuclei_authorization(store, record.authorization_id)\n        binding_ready = \"passive\" in engagement.approved_scan_profiles and (\n            address_class != \"private\" or engagement.private_network_approved\n        )\n    except AssessmentWorkflowError:\n        binding_ready = False\n    if not binding_ready:\n        try:\n            bind_nuclei_authorization(\n                store,\n                authorization_id=record.authorization_id,\n                approved_profiles=(\"passive\",),\n                private_network_approved=address_class == \"private\",\n                recorded_by=principal,\n                approval_basis=(\n                    f\"Interactive authorization for exact target {target.normalized_url}; \"\n                    f\"evidence reference: {evidence}\"\n                ),\n                now=instant,\n            )\n        except (AssessmentWorkflowError, OSError, ValueError) as exc:\n            raise ConversationalAuthorizationError(str(exc)) from exc\n\n    return PreparedConversationalAuthorization(\n        authorization_id=record.authorization_id,\n        target=target.normalized_url,\n        port=target.port,\n        address_class=address_class,\n        reused=reused,\n    )\n'''
(ROOT / "vulnhunter/web/conversational_authorization.py").write_text(helper, encoding="utf-8")

# Wire contextual conversation history and explicit URL authorization into the view.
replace_once(
    "vulnhunter/web/conversational_views.py",
    "from vulnhunter.web.conversation_service import (\n    canonical_target,\n    groq_runtime_status,\n    interpret_request,\n)\n",
    "from vulnhunter.web.conversation_service import (\n    canonical_target,\n    groq_runtime_status,\n    interpret_request,\n)\nfrom vulnhunter.web.conversational_authorization import (\n    ConversationalAuthorizationError,\n    prepare_conversational_authorization,\n)\n",
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    "                    \"Tell me what authorised target you want assessed. I will gather any \"\n                    \"missing details, prepare the bounded Nuclei plan, pause for your \"\n                    \"approval, and continue in this same workspace.\"\n",
    "                    \"Paste an http or https website link. I will identify its path and port, \"\n                    \"check or request authorization, prepare the bounded Nuclei plan, pause for \"\n                    \"your approval and show each live step in this workspace.\"\n",
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    "    interpreted = interpret_request(text, available_profiles=profiles)\n",
    "    context = tuple(\n        (str(item.get(\"role\", \"\")), str(item.get(\"content\", \"\")))\n        for item in _messages(request)[-8:]\n        if isinstance(item, dict)\n    )\n    interpreted = interpret_request(\n        text,\n        available_profiles=profiles,\n        conversation_context=context,\n    )\n",
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    "    if not choices:\n        message = _append_message(\n            request,\n            role=\"assistant\",\n            kind=\"error\",\n            content=(\n                \"No active authorization is available for this account. \"\n                \"Create or prepare an authorization before starting a scan.\"\n            ),\n        )\n        return JsonResponse({\"message\": message}, status=409)\n\n",
    "",
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    "    if matched is None:\n        message = _append_message(\n            request,\n            role=\"assistant\",\n            kind=\"error\",\n            content=\"That target is not present in an active authorization for this account.\",\n        )\n        return JsonResponse({\"message\": message}, status=409)\n",
    "    if matched is None and interpreted.intent == \"authorize\":\n        try:\n            _actor(request, \"scan.create\", \"authorization.create\")\n            prepare_conversational_authorization(\n                target_url=canonical,\n                evidence_reference=interpreted.evidence_reference,\n                identity_id=actor.governance_identity.reviewer_id,\n                username=request.user.get_username(),\n            )\n            choices = workflow.list_authorizations(\n                identity_id=actor.governance_identity.reviewer_id,\n                username=request.user.get_username(),\n            )\n        except WebPermissionDenied as exc:\n            message = _append_message(\n                request, role=\"assistant\", kind=\"error\", content=str(exc)\n            )\n            return JsonResponse({\"message\": message}, status=403)\n        except (ConversationalAuthorizationError, OSError, RuntimeError, ValueError) as exc:\n            state.update({\"target\": canonical, \"profile\": interpreted.profile or \"passive\"})\n            _save_state(request, state)\n            message = _append_message(\n                request,\n                role=\"assistant\",\n                kind=\"authorization_required\",\n                content=str(exc),\n                metadata={\n                    \"suggestions\": [\n                        {\n                            \"label\": \"Add authorization evidence\",\n                            \"message\": (\n                                \"Authorize this target. Evidence: \"\n                                \"<contract, ticket, or bug-bounty scope reference>\"\n                            ),\n                        }\n                    ]\n                },\n            )\n            return JsonResponse({\"message\": message})\n        for item in choices:\n            if any(canonical_target(value) == canonical for value in item.approved_targets):\n                matched = item\n                break\n\n    if matched is None:\n        try:\n            parsed_target = urlsplit(canonical)\n            requested_port = parsed_target.port or (\n                443 if parsed_target.scheme == \"https\" else 80\n            )\n        except ValueError:\n            requested_port = interpreted.port\n        state.update({\"target\": canonical, \"profile\": interpreted.profile or \"passive\"})\n        _save_state(request, state)\n        message = _append_message(\n            request,\n            role=\"assistant\",\n            kind=\"authorization_required\",\n            content=(\n                f\"I recognized {canonical} on port {requested_port}. The URL and port are valid, \"\n                \"but no active authorization covers that exact target yet. Authorize it in chat \"\n                \"and I will continue directly to the passive plan. Public websites need a contract, \"\n                \"ticket, or bug-bounty scope reference.\"\n            ),\n            metadata={\n                \"suggestions\": [\n                    {\n                        \"label\": \"Authorize this target\",\n                        \"message\": (\n                            \"Authorize this target. Evidence: \"\n                            \"<contract, ticket, or bug-bounty scope reference>\"\n                        ),\n                    }\n                ],\n                \"target\": canonical,\n                \"port\": requested_port,\n            },\n        )\n        return JsonResponse({\"message\": message})\n",
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    "    if protocol not in matched.approved_protocols or port not in matched.approved_ports:\n        message = _append_message(\n            request,\n            role=\"assistant\",\n            kind=\"error\",\n            content=\"The requested protocol or port is outside the active authorization.\",\n        )\n        return JsonResponse({\"message\": message}, status=409)\n",
    "    if protocol not in matched.approved_protocols or port not in matched.approved_ports:\n        message = _append_message(\n            request,\n            role=\"assistant\",\n            kind=\"authorization_required\",\n            content=(\n                f\"Port {port} is a valid HTTP/HTTPS service port, but this authorization does \"\n                \"not include it. VulnHunter accepts ports 1 through 65535 once the exact URL and \"\n                \"port are explicitly authorized.\"\n            ),\n        )\n        return JsonResponse({\"message\": message})\n",
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    "        content=(\n            interpreted.assistant_copy\n            or (\n                \"I validated the authorised scope and prepared the exact \"\n                \"Nuclei plan. Review the inline approval card to continue.\"\n            )\n        ),\n",
    "        content=(\n            (\n                \"Authorization recorded. I prepared the exact passive Nuclei plan for the pasted \"\n                \"URL and port. Review the inline approval card to continue.\"\n            )\n            if interpreted.intent == \"authorize\"\n            else (\n                interpreted.assistant_copy\n                or (\n                    \"I validated the authorised scope and prepared the exact \"\n                    \"Nuclei plan. Review the inline approval card to continue.\"\n                )\n            )\n        ),\n",
)

# Make the workspace header describe the primary URL-first workflow.
replace_once(
    "vulnhunter/web/templates/web/conversation.html",
    "Chat naturally about an authorised target. VulnHunter explains each step, pauses for exact-plan confirmation and shows progress as the assessment runs.",
    "Paste an authorised website or link. VulnHunter identifies the path and port, prepares the exact plan, pauses for confirmation and explains progress as the assessment runs.",
)

# Cover URL parsing, arbitrary HTTP ports, public opt-in, and short-lived authorization.
test_file = '''from __future__ import annotations\n\nfrom datetime import UTC, datetime\n\nimport pytest\n\nfrom vulnhunter.authorization.store import AuthorizationStore\nfrom vulnhunter.exceptions import ScopeValidationError\nfrom vulnhunter.scope import validate_target\nfrom vulnhunter.web.assessment_workflow import load_nuclei_authorization\nfrom vulnhunter.web.conversation_service import interpret_request\nfrom vulnhunter.web.conversational_authorization import (\n    ConversationalAuthorizationError,\n    prepare_conversational_authorization,\n)\n\n\ndef test_pasted_website_and_custom_port_are_recognized(settings):\n    settings.VULNHUNTER_GROQ_ENABLED = False\n\n    request = interpret_request(\n        \"https://example.com:54321/login\",\n        available_profiles=(\"passive\",),\n    )\n\n    assert request.intent == \"scan\"\n    assert request.target == \"https://example.com:54321/login\"\n    assert request.port == 54321\n    assert request.protocol == \"https\"\n\n\ndef test_bare_website_is_treated_as_a_scan_target(settings):\n    settings.VULNHUNTER_GROQ_ENABLED = False\n\n    request = interpret_request(\n        \"Please check example.com\",\n        available_profiles=(\"passive\",),\n    )\n\n    assert request.intent == \"scan\"\n    assert request.target == \"http://example.com:80/\"\n\n\ndef test_public_resolution_requires_explicit_opt_in():\n    resolver = lambda _hostname: (\"93.184.216.34\",)\n\n    with pytest.raises(ScopeValidationError, match=\"Public Internet\"):\n        validate_target(\"https://example.com/\", resolver=resolver)\n\n    target = validate_target(\n        \"https://example.com:8443/login\",\n        resolver=resolver,\n        allow_public=True,\n    )\n    assert target.port == 8443\n    assert target.resolved_addresses == (\"93.184.216.34\",)\n\n\ndef test_public_chat_authorization_requires_evidence(tmp_path):\n    store = AuthorizationStore(tmp_path / \"authorization.db\")\n    resolver = lambda _hostname: (\"93.184.216.34\",)\n\n    with pytest.raises(ConversationalAuthorizationError, match=\"evidence reference\"):\n        prepare_conversational_authorization(\n            target_url=\"https://example.com:8443/login\",\n            evidence_reference=None,\n            identity_id=\"vulnhunter-user\",\n            username=\"vulnhunter\",\n            authorization_store=store,\n            resolver=resolver,\n            now=datetime(2026, 7, 23, 18, 0, tzinfo=UTC),\n        )\n\n\ndef test_chat_authorization_accepts_any_valid_http_port(tmp_path):\n    store = AuthorizationStore(tmp_path / \"authorization.db\")\n    instant = datetime(2026, 7, 23, 18, 0, tzinfo=UTC)\n\n    prepared = prepare_conversational_authorization(\n        target_url=\"http://10.0.0.7:65535/\",\n        evidence_reference=None,\n        identity_id=\"vulnhunter-user\",\n        username=\"vulnhunter\",\n        authorization_store=store,\n        now=instant,\n    )\n\n    record, engagement = load_nuclei_authorization(store, prepared.authorization_id)\n    assert prepared.port == 65535\n    assert prepared.address_class == \"private\"\n    assert record.port == 65535\n    assert engagement.approved_ports == (65535,)\n    assert engagement.private_network_approved is True\n\n\ndef test_public_chat_authorization_records_exact_url_and_port(tmp_path):\n    store = AuthorizationStore(tmp_path / \"authorization.db\")\n    resolver = lambda _hostname: (\"93.184.216.34\",)\n    instant = datetime(2026, 7, 23, 18, 0, tzinfo=UTC)\n\n    prepared = prepare_conversational_authorization(\n        target_url=\"https://example.com:8443/login\",\n        evidence_reference=\"Bug bounty scope page BB-2026-17\",\n        identity_id=\"vulnhunter-user\",\n        username=\"vulnhunter\",\n        authorization_store=store,\n        resolver=resolver,\n        now=instant,\n    )\n\n    record, engagement = load_nuclei_authorization(store, prepared.authorization_id)\n    assert record.hostname == \"example.com\"\n    assert record.port == 8443\n    assert record.evidence_reference == \"Bug bounty scope page BB-2026-17\"\n    assert engagement.approved_ports == (8443,)\n    assert engagement.private_network_approved is False\n'''
(ROOT / "tests/unit/test_conversational_url_targets.py").write_text(test_file, encoding="utf-8")

# Include the new module and tests in the focused conversational gate.
replace_all(
    ".github/workflows/conversation-quality.yml",
    "            vulnhunter/web/conversation_service.py \\\n",
    "            vulnhunter/web/conversation_service.py \\\n            vulnhunter/web/conversational_authorization.py \\\n",
    expected=2,
)
replace_all(
    ".github/workflows/conversation-quality.yml",
    "            tests/unit/test_conversation_experience.py \\\n",
    "            tests/unit/test_conversational_url_targets.py \\\n            tests/unit/test_conversation_experience.py \\\n",
    expected=3,
)

print("Applied conversational URL target and authorization intake changes.")
