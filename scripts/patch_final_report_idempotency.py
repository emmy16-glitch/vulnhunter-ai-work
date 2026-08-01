from pathlib import Path

path = Path("vulnhunter/assessment_graph/remediation.py")
text = path.read_text(encoding="utf-8")
old = '''        if normalized == "passed":
            if review.status == NodeStatus.READY:
'''
new = '''        if normalized == "passed":
            if review.status == NodeStatus.COMPLETED:
                return True
            if review.status == NodeStatus.READY:
'''
if text.count(old) != 1:
    raise SystemExit(f"Expected one passed-retest projection block, found {text.count(old)}")
path.write_text(text.replace(old, new), encoding="utf-8")
