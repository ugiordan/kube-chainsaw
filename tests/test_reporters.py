"""Tests for reporters."""

import json

import pytest

from kube_chainsaw.models import Finding, Severity
from kube_chainsaw.reporters import Reporter
from kube_chainsaw.reporters.console import ConsoleReporter
from kube_chainsaw.reporters.json_reporter import JsonReporter
from kube_chainsaw.reporters.sarif import SarifReporter


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        Finding(
            rule_id="KC-001",
            severity=Severity.CRITICAL,
            title="Wildcard resources",
            file="role.yaml",
            description="desc",
            remediation="fix",
            resource_kind="ClusterRole",
            resource_name="admin",
            attack_scenarios=["wildcard_resources"],
        ),
        Finding(
            rule_id="KC-006",
            severity=Severity.HIGH,
            title="Secrets access",
            file="role.yaml",
            description="desc",
            remediation="fix",
            resource_kind="ClusterRole",
            resource_name="reader",
        ),
    ]


class TestConsoleReporter:
    """Tests for ConsoleReporter."""

    def test_is_reporter(self):
        """ConsoleReporter should inherit from Reporter."""
        reporter = ConsoleReporter()
        assert isinstance(reporter, Reporter)

    def test_render_contains_rule_id_and_severity(self, sample_findings):
        """Output should contain rule ID and severity."""
        reporter = ConsoleReporter()
        output = reporter.render(sample_findings)

        assert "KC-001" in output
        assert "KC-006" in output
        assert "CRITICAL" in output
        assert "HIGH" in output

    def test_render_strips_scenarios_by_default(self, sample_findings):
        """Attack scenarios should not appear in output by default."""
        reporter = ConsoleReporter()
        output = reporter.render(sample_findings)

        assert "wildcard_resources" not in output
        assert "attack_scenarios" not in output.lower()

    def test_render_includes_scenarios_when_enabled(self, sample_findings):
        """Attack scenarios should appear when include_scenarios=True."""
        reporter = ConsoleReporter()
        output = reporter.render(sample_findings, include_scenarios=True)

        assert "wildcard_resources" in output

    def test_render_groups_by_severity(self, sample_findings):
        """Findings should be grouped by severity with CRITICAL first."""
        reporter = ConsoleReporter()
        output = reporter.render(sample_findings)

        critical_pos = output.find("CRITICAL")
        high_pos = output.find("HIGH")
        assert critical_pos < high_pos

    def test_render_shows_totals(self, sample_findings):
        """Output should show total count and counts per severity."""
        reporter = ConsoleReporter()
        output = reporter.render(sample_findings)

        assert "2" in output  # total count
        assert "1" in output  # per-severity counts


class TestJsonReporter:
    """Tests for JsonReporter."""

    def test_is_reporter(self):
        """JsonReporter should inherit from Reporter."""
        reporter = JsonReporter()
        assert isinstance(reporter, Reporter)

    def test_render_returns_valid_json(self, sample_findings):
        """Output should be valid JSON."""
        reporter = JsonReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        assert "findings" in data

    def test_render_correct_count(self, sample_findings):
        """JSON should contain correct number of findings."""
        reporter = JsonReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        assert len(data["findings"]) == 2

    def test_render_strips_scenarios_by_default(self, sample_findings):
        """Attack scenarios should not appear in JSON by default."""
        reporter = JsonReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        for finding in data["findings"]:
            assert "attack_scenarios" not in finding

    def test_render_includes_scenarios_when_enabled(self, sample_findings):
        """Attack scenarios should appear in JSON when include_scenarios=True."""
        reporter = JsonReporter()
        output = reporter.render(sample_findings, include_scenarios=True)

        data = json.loads(output)
        # First finding has scenarios
        assert "attack_scenarios" in data["findings"][0]
        assert data["findings"][0]["attack_scenarios"] == ["wildcard_resources"]

    def test_render_includes_fingerprint(self, sample_findings):
        """Each finding should include fingerprint."""
        reporter = JsonReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        for finding in data["findings"]:
            assert "fingerprint" in finding
            assert finding["fingerprint"]  # not empty

    def test_render_includes_suppressed_flag(self, sample_findings):
        """Each finding should include suppressed flag."""
        reporter = JsonReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        for finding in data["findings"]:
            assert "suppressed" in finding
            assert finding["suppressed"] is False


class TestSarifReporter:
    """Tests for SarifReporter."""

    def test_is_reporter(self):
        """SarifReporter should inherit from Reporter."""
        reporter = SarifReporter()
        assert isinstance(reporter, Reporter)

    def test_render_returns_valid_sarif_structure(self, sample_findings):
        """Output should be valid SARIF 2.1.0."""
        reporter = SarifReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_render_populates_tool_info(self, sample_findings):
        """SARIF should include tool name and version."""
        reporter = SarifReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "kube-chainsaw"
        assert "version" in tool

    def test_render_populates_rule_ids(self, sample_findings):
        """SARIF rules array should contain unique rule IDs."""
        reporter = SarifReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "KC-001" in rule_ids
        assert "KC-006" in rule_ids

    def test_render_results_reference_rules(self, sample_findings):
        """SARIF results should reference rule IDs."""
        reporter = SarifReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 2
        assert all("ruleId" in r for r in results)

    def test_render_never_includes_attack_scenarios(self, sample_findings):
        """SARIF should never include attack scenarios regardless of flag."""
        reporter = SarifReporter()

        # Without flag
        output_without = reporter.render(sample_findings, include_scenarios=False)
        assert "attack_scenarios" not in output_without
        assert "wildcard_resources" not in output_without

        # With flag
        output_with = reporter.render(sample_findings, include_scenarios=True)
        assert "attack_scenarios" not in output_with
        assert "wildcard_resources" not in output_with

    def test_render_includes_locations(self, sample_findings):
        """SARIF results should include file locations."""
        reporter = SarifReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        results = data["runs"][0]["results"]
        for result in results:
            assert "locations" in result
            assert len(result["locations"]) > 0

    def test_render_maps_severity_levels(self, sample_findings):
        """SARIF should map severity to correct SARIF levels."""
        reporter = SarifReporter()
        output = reporter.render(sample_findings)

        data = json.loads(output)
        results = data["runs"][0]["results"]

        # Find CRITICAL and HIGH findings
        critical_result = next(r for r in results if r["ruleId"] == "KC-001")
        high_result = next(r for r in results if r["ruleId"] == "KC-006")

        assert critical_result["level"] == "error"
        assert high_result["level"] == "error"
