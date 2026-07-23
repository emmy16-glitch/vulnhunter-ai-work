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


def call_block(marker: str) -> tuple[int, int, str]:
    start = content.find(marker)
    if start < 0:
        raise RuntimeError(f"Could not locate patch call: {marker}")
    end = content.find("\n)\n", start)
    if end < 0:
        raise RuntimeError(f"Could not locate end of patch call: {marker}")
    end += len("\n)\n")
    return start, end, content[start:end]


def upgrade_call(marker: str, *, expected: int) -> None:
    global content
    start, end, block = call_block(marker)
    replacement = block.replace("replace_once(", "replace_all(", 1)
    replacement = replacement[:-3] + f"\n    expected={expected},\n)\n"
    content = content[:start] + replacement + content[end:]


upgrade_call(
    'replace_once(\n    ".github/workflows/conversation-quality.yml",\n'
    "    '''            vulnhunter/web/conversation_service.py",
    expected=2,
)
upgrade_call(
    'replace_once(\n    ".github/workflows/conversation-quality.yml",\n'
    "    '''            tests/unit/test_chat_runtime_reply.py \\\\n"
    "            tests/unit/test_conversational_url_targets.py",
    expected=3,
)

redundant_marker = (
    'replace_once(\n    ".github/workflows/conversation-quality.yml",\n'
    "    '''            tests/unit/test_chat_runtime_reply.py \\\\n"
    "            tests/unit/test_conversational_url_targets.py \\\\n"
    "            tests/unit/test_conversation_experience.py"
)
start, end, _ = call_block(redundant_marker)
content = content[:start] + content[end:]

env_marker = (
    'replace_once(\n    ".github/workflows/quality.yml",\n'
    "    '      VULNHUNTER_INTELLIGENCE_ENABLED: \"false\"\\n',"
)
start, end, block = call_block(env_marker)
block = block.replace(
    "    '      VULNHUNTER_INTELLIGENCE_ENABLED: \"false\"\\n',",
    "    '''      VULNHUNTER_UI_BASE_URL: http://127.0.0.1:8767\\n"
    "      VULNHUNTER_INTELLIGENCE_ENABLED: \"false\"\\n''',",
    1,
)
block = block.replace(
    "    '''      VULNHUNTER_INTELLIGENCE_ENABLED: \"false\"\\n",
    "    '''      VULNHUNTER_UI_BASE_URL: http://127.0.0.1:8767\\n"
    "      VULNHUNTER_INTELLIGENCE_ENABLED: \"false\"\\n",
    1,
)
content = content[:start] + block + content[end:]

namespace = {"__name__": "__main__", "__file__": str(path)}
exec(compile(content, str(path), "exec"), namespace)
