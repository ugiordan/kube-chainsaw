"""Console reporter for human-readable output."""

from collections import defaultdict
from typing import List

from kube_chainsaw.models import Finding, Severity
from kube_chainsaw.reporters import Reporter


class ConsoleReporter(Reporter):
    """Human-readable console output reporter."""

    def render(self, findings: List[Finding]) -> str:
        if not findings:
            return "No findings.\n"

        by_severity = defaultdict(list)
        for finding in findings:
            by_severity[finding.severity].append(finding)

        lines = []
        lines.append("=" * 80)
        lines.append("Security Findings Report")
        lines.append("=" * 80)
        lines.append("")

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
                lines.append("")

        lines.append("=" * 80)
        lines.append(f"Total findings: {len(findings)}")
        for severity in severity_order:
            if severity in by_severity:
                lines.append(f"  {severity.name}: {len(by_severity[severity])}")
        lines.append("=" * 80)

        return "\n".join(lines)
