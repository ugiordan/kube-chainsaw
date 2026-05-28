"""End-to-end integration tests for kube-chainsaw CLI."""

import json
import os
import subprocess

import pytest


# Path to venv Python executable
VENV_PYTHON = os.path.join(
    os.path.dirname(__file__), "..", ".venv", "bin", "python"
)


def run_kc(*args):
    """Run kube-chainsaw CLI with given arguments.

    Returns:
        subprocess.CompletedProcess with stdout, stderr, and returncode.
    """
    return subprocess.run(
        [VENV_PYTHON, "-m", "kube_chainsaw.cli", *args],
        capture_output=True,
        text=True,
    )


class TestEndToEnd:
    """End-to-end integration tests using subprocess to test the full CLI."""

    def test_dangerous_produces_findings(self, dangerous_dir, tmp_path):
        """Verify that scanning dangerous manifests produces findings and fails."""
        out = tmp_path / "findings.json"
        r = run_kc(str(dangerous_dir), "--output", str(out), "--fail-on", "INFO")
        # Should exit with error code
        assert r.returncode == 1
        # Should produce findings
        data = json.loads(out.read_text())
        assert len(data["findings"]) > 0

    def test_clean_produces_no_findings(self, clean_dir, tmp_path):
        """Verify that scanning clean manifests produces no findings and succeeds."""
        out = tmp_path / "findings.json"
        r = run_kc(str(clean_dir), "--output", str(out))
        # Should succeed
        assert r.returncode == 0
        # Should have no findings
        data = json.loads(out.read_text())
        assert len(data["findings"]) == 0

    def test_sarif_output_valid(self, dangerous_dir, tmp_path):
        """Verify that SARIF output format is valid."""
        out = tmp_path / "results.sarif"
        r = run_kc(str(dangerous_dir), "--output", str(out))
        # Should produce valid SARIF
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) > 0
        assert len(data["runs"][0]["results"]) > 0

    def test_suppression_marks_findings(self, dangerous_dir, tmp_path):
        """Verify that suppressions mark findings as suppressed."""
        # First run to discover findings
        out1 = tmp_path / "f1.json"
        run_kc(str(dangerous_dir), "--output", str(out1))
        data1 = json.loads(out1.read_text())
        assert len(data1["findings"]) > 0
        first = data1["findings"][0]

        # Create suppression file
        supp = tmp_path / "supp.yaml"
        supp.write_text(
            f"suppressions:\n"
            f"  - rule_id: {first['rule_id']}\n"
            f"    resource_name: {first['resource_name']}\n"
            f"    reason: test suppression\n"
        )

        # Re-run with suppression
        out2 = tmp_path / "f2.json"
        run_kc(str(dangerous_dir), "--output", str(out2), "--suppressions", str(supp))
        data2 = json.loads(out2.read_text())

        # Should have at least one suppressed finding
        suppressed = [f for f in data2["findings"] if f.get("suppressed")]
        assert len(suppressed) >= 1

    def test_multiple_paths(self, dangerous_dir, clean_dir, tmp_path):
        """Verify that multiple paths can be scanned in one run."""
        out = tmp_path / "f.json"
        r = run_kc(str(dangerous_dir), str(clean_dir), "--output", str(out))
        data = json.loads(out.read_text())
        # Should have findings from dangerous dir
        assert len(data["findings"]) > 0

    def test_help_output(self):
        """Verify that --help works and shows usage."""
        r = run_kc("--help")
        assert r.returncode == 0
        assert "kube-chainsaw" in r.stdout.lower() or "usage" in r.stdout.lower()

    def test_version_output(self):
        """Verify that --version works."""
        r = run_kc("--version")
        assert r.returncode == 0
        # Should output version number
        assert r.stdout.strip() != ""

    def test_nonexistent_path_handled(self, tmp_path):
        """Verify that nonexistent paths are handled gracefully."""
        out = tmp_path / "out.json"
        fake_path = tmp_path / "does-not-exist"
        r = run_kc(str(fake_path), "--output", str(out))
        # Should succeed but warn
        assert r.returncode == 0
        data = json.loads(out.read_text())
        assert len(data["findings"]) == 0

    def test_fail_on_severity_warning(self, dangerous_dir, tmp_path):
        """Verify that --fail-on WARNING fails when warning+ severity findings exist."""
        out = tmp_path / "out.json"
        r = run_kc(str(dangerous_dir), "--output", str(out), "--fail-on", "WARNING")
        data = json.loads(out.read_text())
        # If there are any WARNING, HIGH, or CRITICAL findings, should fail
        failing_findings = [
            f for f in data["findings"]
            if f.get("severity") in ["WARNING", "HIGH", "CRITICAL"] and not f.get("suppressed")
        ]
        if len(failing_findings) > 0:
            assert r.returncode == 1

    def test_fail_on_severity_critical_only(self, dangerous_dir, tmp_path):
        """Verify that --fail-on CRITICAL only fails on critical findings."""
        out = tmp_path / "out.json"
        r = run_kc(str(dangerous_dir), "--output", str(out), "--fail-on", "CRITICAL")
        data = json.loads(out.read_text())
        # Should only fail if there's a critical finding
        critical_findings = [
            f for f in data["findings"]
            if f.get("severity") == "CRITICAL" and not f.get("suppressed")
        ]
        if len(critical_findings) > 0:
            assert r.returncode == 1
        else:
            assert r.returncode == 0

    def test_json_output_structure(self, dangerous_dir, tmp_path):
        """Verify that JSON output has expected structure."""
        out = tmp_path / "out.json"
        run_kc(str(dangerous_dir), "--output", str(out))
        data = json.loads(out.read_text())

        # Check top-level structure
        assert "findings" in data
        assert isinstance(data["findings"], list)

        # Check finding structure (if findings exist)
        if len(data["findings"]) > 0:
            finding = data["findings"][0]
            assert "rule_id" in finding
            assert "severity" in finding
            assert "title" in finding
            assert "description" in finding
            assert "resource_name" in finding
            assert "file" in finding
            assert "fingerprint" in finding
