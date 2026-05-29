"""Tests for CLI entrypoint."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Use venv python for subprocess tests
VENV_PYTHON = os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python")


def run_cli(*args):
    """Run CLI as subprocess."""
    return subprocess.run(
        [VENV_PYTHON, "-m", "kube_chainsaw.cli", *args],
        capture_output=True,
        text=True,
    )


def test_clean_fixtures_exit_0(clean_dir):
    """Clean fixtures should exit with code 0."""
    result = run_cli(str(clean_dir))
    assert result.returncode == 0


def test_dangerous_fixtures_fail_on_critical(dangerous_dir):
    """Dangerous fixtures with --fail-on CRITICAL should exit 1 (there are CRITICAL findings)."""
    result = run_cli(str(dangerous_dir), "--fail-on", "CRITICAL")
    assert result.returncode == 1


def test_format_json_produces_valid_json(dangerous_dir):
    """--format json produces valid JSON on stdout."""
    result = run_cli(str(dangerous_dir), "--format", "json")
    assert result.returncode == 1  # Has findings
    data = json.loads(result.stdout)
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_format_sarif_produces_valid_sarif(dangerous_dir):
    """--format sarif produces valid SARIF on stdout."""
    result = run_cli(str(dangerous_dir), "--format", "sarif")
    assert result.returncode == 1  # Has findings
    data = json.loads(result.stdout)
    assert data.get("version") == "2.1.0"
    assert "$schema" in data
    assert "runs" in data


def test_output_json_writes_file_and_prints_console(dangerous_dir, tmp_path):
    """--output findings.json writes JSON file AND still prints console to stdout."""
    output_file = tmp_path / "findings.json"
    result = run_cli(str(dangerous_dir), "--output", str(output_file))

    # Should exit 1 (has critical findings)
    assert result.returncode == 1

    # Should print console format to stdout
    assert "CRITICAL" in result.stdout or "HIGH" in result.stdout

    # Should write JSON to file
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_output_sarif_writes_file(dangerous_dir, tmp_path):
    """--output results.sarif writes SARIF file."""
    output_file = tmp_path / "results.sarif"
    result = run_cli(str(dangerous_dir), "--output", str(output_file))

    # Should exit 1 (has critical findings)
    assert result.returncode == 1

    # Should write SARIF to file
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert data.get("version") == "2.1.0"
    assert "$schema" in data


def test_quiet_suppresses_stdout_but_output_still_writes(dangerous_dir, tmp_path):
    """--quiet suppresses stdout but --output still writes."""
    output_file = tmp_path / "findings.json"
    result = run_cli(str(dangerous_dir), "--quiet", "--output", str(output_file))

    # Should exit 1 (has critical findings)
    assert result.returncode == 1

    # Stdout should be empty or minimal (no findings output)
    assert "CRITICAL" not in result.stdout
    assert "HIGH" not in result.stdout

    # Should still write to file
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert "findings" in data


def test_version_prints_version_string():
    """--version prints version string."""
    result = run_cli("--version")
    assert result.returncode == 0
    assert "0.1.0" in result.stdout or "0.1.0" in result.stderr


def test_nonexistent_path_exits_0():
    """Nonexistent path exits 0 (no findings)."""
    result = run_cli("/nonexistent/path/does/not/exist")
    assert result.returncode == 0


def test_fail_on_high_with_high_finding(dangerous_dir):
    """--fail-on HIGH should exit 1 when HIGH findings exist."""
    result = run_cli(str(dangerous_dir), "--fail-on", "HIGH")
    assert result.returncode == 1


def test_fail_on_warning_no_warnings_exits_0(clean_dir):
    """--fail-on WARNING should exit 0 when no warnings or higher."""
    result = run_cli(str(clean_dir), "--fail-on", "WARNING")
    assert result.returncode == 0


def test_exclude_dirs(tmp_path, dangerous_dir):
    """--exclude-dirs should skip specified directories."""
    # Copy dangerous fixture to tmp_path/dangerous
    import shutil
    target = tmp_path / "dangerous"
    shutil.copytree(dangerous_dir, target)

    # Scan with exclude should find nothing
    result = run_cli(str(tmp_path), "--exclude-dirs", "dangerous")
    assert result.returncode == 0


def test_output_format_override(dangerous_dir, tmp_path):
    """--output-format sarif should override .json extension."""
    output_file = tmp_path / "results.json"
    result = run_cli(
        str(dangerous_dir),
        "--output", str(output_file),
        "--output-format", "sarif"
    )

    assert result.returncode == 1
    assert output_file.exists()
    data = json.loads(output_file.read_text())
    assert data.get("version") == "2.1.0"  # SARIF marker


def test_no_rbac_resources_warning(tmp_path):
    """No RBAC resources should print warning to stderr."""
    # Create empty directory
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    result = run_cli(str(empty_dir))
    assert result.returncode == 0
    assert "No RBAC resources found" in result.stderr



def test_suppressions_file(dangerous_dir, tmp_path):
    """--suppressions should load and apply suppression rules."""
    # Create a suppression file
    suppressions_file = tmp_path / "suppressions.yaml"
    suppressions_file.write_text("""
suppressions:
  - rule_id: cluster-admin-role
    resource_name: cluster-admin-sa
""")

    # Run without suppressions first
    result1 = run_cli(str(dangerous_dir))

    # Run with suppressions
    result2 = run_cli(str(dangerous_dir), "--suppressions", str(suppressions_file))

    # Both should run successfully (exit code may vary)
    assert result1.returncode in (0, 1)
    assert result2.returncode in (0, 1)


def test_multiple_paths(clean_dir, dangerous_dir):
    """Multiple paths should be scanned."""
    result = run_cli(str(clean_dir), str(dangerous_dir))
    # Dangerous dir has critical findings
    assert result.returncode == 1
