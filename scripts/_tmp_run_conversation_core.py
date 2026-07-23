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


PREFIX = 'replace_once(\n    ".github/workflows/conversation-quality.yml",'


def workflow_blocks() -> list[tuple[int, int, str]]:
    blocks: list[tuple[int, int, str]] = []
    cursor = 0
    while True:
        start = content.find(PREFIX, cursor)
        if start < 0:
            return blocks
        end = content.find("\n)\n", start)
        if end < 0:
            raise RuntimeError("Could not find the end of a conversation-quality patch call")
        end += len("\n)\n")
        blocks.append((start, end, content[start:end]))
        cursor = end


def replace_block(predicate, transform) -> None:
    global content
    matches = [item for item in workflow_blocks() if predicate(item[2])]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one workflow patch block, found {len(matches)}")
    start, end, block = matches[0]
    content = content[:start] + transform(block) + content[end:]


def make_replace_all(block: str, expected: int) -> str:
    result = block.replace("replace_once(", "replace_all(", 1)
    return result[:-3] + f"\n    expected={expected},\n)\n"


replace_block(
    lambda block: "vulnhunter/web/conversation_service.py" in block,
    lambda block: make_replace_all(block, 2),
)
replace_block(
    lambda block: (
        "tests/unit/test_chat_runtime_reply.py" in block
        and "tests/unit/test_conversation_experience.py" not in block
    ),
    lambda block: make_replace_all(block, 3),
)
replace_block(
    lambda block: (
        "tests/unit/test_chat_runtime_reply.py" in block
        and "tests/unit/test_conversation_experience.py" in block
    ),
    lambda _block: "",
)

quality_prefix = 'replace_once(\n    ".github/workflows/quality.yml",'
start = content.find(quality_prefix)
if start < 0:
    raise RuntimeError("Could not find the quality workflow environment patch")
end = content.find("\n)\n", start)
if end < 0:
    raise RuntimeError("Could not find the end of the quality workflow environment patch")
end += len("\n)\n")
block = content[start:end]
if "VULNHUNTER_INTELLIGENCE_ENABLED" not in block:
    raise RuntimeError("The first quality workflow patch was not the expected environment patch")
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
