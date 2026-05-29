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
    def test_is_reporter(self):
        assert isinstance(ConsoleReporter(), Reporter)

    def test_render_contains_rule_id_and_severity(self, sample_findings):
        output = ConsoleReporter().render(sample_findings)
        assert "KC-001" in output
        assert "KC-006" in output
        assert "CRITICAL" in output
        assert "HIGH" in output

    def test_render_groups_by_severity(self, sample_findings):
        output = ConsoleReporter().render(sample_findings)
        assert output.find("CRITICAL") < output.find("HIGH")

    def test_render_shows_totals(self, sample_findings):
        output = ConsoleReporter().render(sample_findings)
        assert "Total findings: 2" in output


class TestJsonReporter:
    def test_is_reporter(self):
        assert isinstance(JsonReporter(), Reporter)

    def test_render_returns_valid_json(self, sample_findings):
        data = json.loads(JsonReporter().render(sample_findings))
        assert "findings" in data

    def test_render_correct_count(self, sample_findings):
        data = json.loads(JsonReporter().render(sample_findings))
        assert len(data["findings"]) == 2

    def test_render_includes_fingerprint(self, sample_findings):
        data = json.loads(JsonReporter().render(sample_findings))
        for finding in data["findings"]:
            assert finding["fingerprint"]

    def test_render_includes_suppressed_flag(self, sample_findings):
        data = json.loads(JsonReporter().render(sample_findings))
        for finding in data["findings"]:
            assert finding["suppressed"] is False


class TestSarifReporter:
    def test_is_reporter(self):
        assert isinstance(SarifReporter(), Reporter)

    def test_render_returns_valid_sarif_structure(self, sample_findings):
        data = json.loads(SarifReporter().render(sample_findings))
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1

    def test_render_populates_tool_info(self, sample_findings):
        data = json.loads(SarifReporter().render(sample_findings))
        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "kube-chainsaw"

    def test_render_populates_rule_ids(self, sample_findings):
        data = json.loads(SarifReporter().render(sample_findings))
        rule_ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
        assert "KC-001" in rule_ids
        assert "KC-006" in rule_ids

    def test_render_results_reference_rules(self, sample_findings):
        data = json.loads(SarifReporter().render(sample_findings))
        results = data["runs"][0]["results"]
        assert len(results) == 2
        assert all("ruleId" in r for r in results)

    def test_render_includes_locations(self, sample_findings):
        data = json.loads(SarifReporter().render(sample_findings))
        for result in data["runs"][0]["results"]:
            assert len(result["locations"]) > 0

    def test_render_maps_severity_levels(self, sample_findings):
        data = json.loads(SarifReporter().render(sample_findings))
        results = data["runs"][0]["results"]
        critical_result = next(r for r in results if r["ruleId"] == "KC-001")
        high_result = next(r for r in results if r["ruleId"] == "KC-006")
        assert critical_result["level"] == "error"
        assert high_result["level"] == "error"
