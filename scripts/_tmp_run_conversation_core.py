from __future__ import annotations

from pathlib import Path


path = Path(__file__).with_name("_tmp_apply_conversation_core.py")
content = path.read_text(encoding="utf-8")
content = content.replace(
    "updated, count = re.subn(pattern, replacement, content, count=1, flags=re.DOTALL)",
    "updated, count = re.subn("
    "pattern, lambda _match: replacement, content, count=1, flags=re.DOTALL"
    ")",
    1,
)
helper_anchor = "def regex_once(path: str, pattern: str, replacement: str) -> None:\n"
helper = '''def replace_all(path: str, old: str, new: str, *, expected: int) -> None:
    content = read(path)
    count = content.count(old)
    if count != expected:
        raise RuntimeError(
            f"Expected {expected} matches in {path}, found {count}: {old[:120]!r}"
        )
    write(path, content.replace(old, new))


'''
if "def replace_all(" not in content:
    content = content.replace(helper_anchor, helper + helper_anchor, 1)

module_old = '''replace_once(
    ".github/workflows/conversation-quality.yml",
    \'\'\'            vulnhunter/web/conversation_service.py \\
            vulnhunter/web/conversational_authorization.py \\
            vulnhunter/web/conversational_views.py \\
\'\'\',
    \'\'\'            vulnhunter/web/conversation_service.py \\
            vulnhunter/web/conversation_state.py \\
            vulnhunter/web/conversational_authorization.py \\
            vulnhunter/web/conversational_views.py \\
\'\'\',
)'''
module_new = module_old.replace("replace_once(", "replace_all(", 1).replace(
    "\n)", "\n    expected=2,\n)", 1
)
content = content.replace(module_old, module_new, 1)

tests_old = '''replace_once(
    ".github/workflows/conversation-quality.yml",
    \'\'\'            tests/unit/test_chat_runtime_reply.py \\
            tests/unit/test_conversational_url_targets.py \\
\'\'\',
    \'\'\'            tests/unit/test_chat_runtime_reply.py \\
            tests/unit/test_conversation_core_redesign.py \\
            tests/unit/test_conversational_url_targets.py \\
\'\'\',
)'''
tests_new = tests_old.replace("replace_once(", "replace_all(", 1).replace(
    "\n)", "\n    expected=3,\n)", 1
)
content = content.replace(tests_old, tests_new, 1)

redundant = '''replace_once(
    ".github/workflows/conversation-quality.yml",
    \'\'\'            tests/unit/test_chat_runtime_reply.py \\
            tests/unit/test_conversational_url_targets.py \\
            tests/unit/test_conversation_experience.py \\
\'\'\',
    \'\'\'            tests/unit/test_chat_runtime_reply.py \\
            tests/unit/test_conversation_core_redesign.py \\
            tests/unit/test_conversational_url_targets.py \\
            tests/unit/test_conversation_experience.py \\
\'\'\',
)
'''
content = content.replace(redundant, "", 1)

env_old = '''replace_once(
    ".github/workflows/quality.yml",
    '      VULNHUNTER_INTELLIGENCE_ENABLED: "false"\\n',
    \'\'\'      VULNHUNTER_INTELLIGENCE_ENABLED: "false"\\n      VULNHUNTER_NUCLEI_READINESS_REPORT: /tmp/vh-ui/nuclei-readiness.json\\n      VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED: "true"\\n      VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE: /tmp/vh-ui/worker-signing.key\\n      VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT: /tmp/vh-ui/worker-spool\\n\'\'\',
)'''
env_new = '''replace_once(
    ".github/workflows/quality.yml",
    \'\'\'      VULNHUNTER_UI_BASE_URL: http://127.0.0.1:8767\\n      VULNHUNTER_INTELLIGENCE_ENABLED: "false"\\n\'\'\',
    \'\'\'      VULNHUNTER_UI_BASE_URL: http://127.0.0.1:8767\\n      VULNHUNTER_INTELLIGENCE_ENABLED: "false"\\n      VULNHUNTER_NUCLEI_READINESS_REPORT: /tmp/vh-ui/nuclei-readiness.json\\n      VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED: "true"\\n      VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE: /tmp/vh-ui/worker-signing.key\\n      VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT: /tmp/vh-ui/worker-spool\\n\'\'\',
)'''
content = content.replace(env_old, env_new, 1)

namespace = {"__name__": "__main__", "__file__": str(path)}
exec(compile(content, str(path), "exec"), namespace)
