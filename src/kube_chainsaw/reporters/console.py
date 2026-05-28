"""Console reporter for human-readable output."""

from collections import defaultdict
from typing import List

from kube_chainsaw.models import Finding, Severity
from kube_chainsaw.reporters import Reporter


class ConsoleReporter(Reporter):
    """Human-readable console output reporter."""

    def render(self, findings: List[Finding], include_scenarios: bool = False) -> str:
        """Render findings to human-readable console output.

        Args:
            findings: List of findings to render.
            include_scenarios: Whether to include attack scenarios in output.

        Returns:
            Formatted console output.
        """
        if not findings:
            return "No findings.\n"

        # Group findings by severity
        by_severity = defaultdict(list)
        for finding in findings:
            by_severity[finding.severity].append(finding)

        # Build output with severity groups (CRITICAL first, descending)
        lines = []
        lines.append("=" * 80)
        lines.append("Security Findings Report")
        lines.append("=" * 80)
        lines.append("")

        # Severity order: CRITICAL, HIGH, WARNING, INFO
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.WARNING, Severity.INFO]

        for severity in severity_order:
            if severity not in by_severity:
                continue

            severity_findings = by_severity[severity]
            lines.append(f"{severity.name} ({len(severity_findings)})")
            lines.append("-" * 80)

            for finding in severity_findings:
                lines.append(f"  Rule ID: {finding.rule_id}")
                lines.append(f"  Title: {finding.title}")
                lines.append(f"  File: {finding.file}")
                lines.append(f"  Resource: {finding.resource_kind}/{finding.resource_name}")
                lines.append(f"  Description: {finding.description}")
                lines.append(f"  Remediation: {finding.remediation}")

                if include_scenarios and finding.attack_scenarios:
                    lines.append(f"  Attack Scenarios:")
                    for scenario in finding.attack_scenarios:
                        lines.append(f"    - {scenario}")

                lines.append("")

        # Add summary
        lines.append("=" * 80)
        lines.append(f"Total findings: {len(findings)}")
        for severity in severity_order:
            if severity in by_severity:
                lines.append(f"  {severity.name}: {len(by_severity[severity])}")
        lines.append("=" * 80)

        return "\n".join(lines)
