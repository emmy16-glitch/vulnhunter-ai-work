from typer.testing import CliRunner

from vulnhunter.cli import app

runner = CliRunner()


def test_scan_list_initializes_empty_database(tmp_path):
    database = tmp_path / "cli.db"
    result = runner.invoke(app, ["scan", "list", "--database", str(database)])
    assert result.exit_code == 0
    assert "No scans found" in result.stdout
    assert database.exists()


def test_findings_list_rejects_invalid_label(tmp_path):
    database = tmp_path / "cli.db"
    result = runner.invoke(
        app,
        ["findings", "list", "--database", str(database), "--label", "wrong"],
    )
    assert result.exit_code == 2
    assert "Invalid filter" in result.output
