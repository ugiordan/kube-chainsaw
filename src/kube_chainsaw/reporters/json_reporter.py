"""JSON reporter for structured output."""

import json
from typing import Any, Dict, List

from kube_chainsaw.models import Finding
from kube_chainsaw.reporters import Reporter


class JsonReporter(Reporter):
    """JSON output reporter."""

    def render(self, findings: List[Finding]) -> str:
        findings_data: List[Dict[str, Any]] = []

        for finding in findings:
            finding_dict: Dict[str, Any] = {
                "rule_id": finding.rule_id,
                "severity": finding.severity.name,
                "title": finding.title,
                "file": finding.file,
                "description": finding.description,
                "remediation": finding.remediation,
                "resource_kind": finding.resource_kind,
                "resource_name": finding.resource_name,
                "resource_namespace": finding.resource_namespace,
                "fingerprint": finding.fingerprint,
                "suppressed": finding.suppressed,
            }

            findings_data.append(finding_dict)

        output = {"findings": findings_data}
        return json.dumps(output, indent=2)
