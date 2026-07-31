"""Temporary branch-only compile shim for the generated implementation runner."""

from __future__ import annotations

import builtins

_REAL_COMPILE = builtins.compile

_AMBIGUOUS = r"""views = replace_once(
    views,
    '            username=request.user.get_username(),\n        )\n',
    '            username=request.user.get_username(),\n'
    '            workspace_id=(\n'
    '                str(request.vulnhunter_thread.thread_id)\n'
    '                if getattr(request, "vulnhunter_thread", None) is not None\n'
    '                else None\n'
    '            ),\n'
    '        )\n',
)
"""

_SPECIFIC = r"""views = replace_once(
    views,
    '        result = workflow.create_assessment(\n'
    '            authorization_id=matched.authorization_id,\n'
    '            target=canonical,\n'
    '            protocol=protocol,\n'
    '            port=port,\n'
    '            profile=profile,\n'
    '            identity_id=actor.governance_identity.reviewer_id,\n'
    '            username=request.user.get_username(),\n'
    '        )\n',
    '        result = workflow.create_assessment(\n'
    '            authorization_id=matched.authorization_id,\n'
    '            target=canonical,\n'
    '            protocol=protocol,\n'
    '            port=port,\n'
    '            profile=profile,\n'
    '            identity_id=actor.governance_identity.reviewer_id,\n'
    '            username=request.user.get_username(),\n'
    '            workspace_id=(\n'
    '                str(request.vulnhunter_thread.thread_id)\n'
    '                if getattr(request, "vulnhunter_thread", None) is not None\n'
    '                else None\n'
    '            ),\n'
    '        )\n',
)
"""


def _compile(
    source,
    filename,
    mode,
    flags=0,
    dont_inherit=False,
    optimize=-1,
    *,
    _feature_version=-1,
):
    if filename == "chat-taskgraph-generated.py" and isinstance(source, str):
        if _AMBIGUOUS not in source:
            raise RuntimeError("expected generated assessment patch was not found")
        source = source.replace(_AMBIGUOUS, _SPECIFIC, 1)
    return _REAL_COMPILE(
        source,
        filename,
        mode,
        flags,
        dont_inherit,
        optimize,
        _feature_version=_feature_version,
    )


builtins.compile = _compile
