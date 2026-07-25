from pathlib import Path

from vulnhunter.security_tools.worker_spool import load_worker_signing_key

ROOT = Path(__file__).resolve().parents[2]
ACCEPTANCE = ROOT / "scripts" / "phone_lab_acceptance.py"


def test_worker_key_loader_normalizes_boundary_whitespace(tmp_path):
    key_path = tmp_path / "worker.key"
    key_path.write_bytes(b"\n" + (b"x" * 48) + b"\t")
    key_path.chmod(0o600)

    assert load_worker_signing_key(key_path) == b"x" * 48


def test_phone_lab_manager_and_worker_use_the_same_key_loader():
    source = ACCEPTANCE.read_text(encoding="utf-8")

    assert "load_worker_signing_key" in source
    assert 'signing_key=load_worker_signing_key(paths["key"])' in source
    assert 'signing_key=paths["key"].read_bytes()' not in source
