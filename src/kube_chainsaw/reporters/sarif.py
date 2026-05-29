"""SARIF reporter for standardized security output."""

import json
from typing import Any, Dict, List

from kube_chainsaw import __version__
from kube_chainsaw.models import Finding, Severity
from kube_chainsaw.reporters import Reporter


class SarifReporter(Reporter):
    """SARIF 2.1.0 output reporter."""

    def render(self, findings: List[Finding]) -> str:
        # Build unique rules from findings
        rules_dict: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            if finding.rule_id not in rules_dict:
                rules_dict[finding.rule_id] = {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.title},
                }

        rules = list(rules_dict.values())

        # Build results
        results: List[Dict[str, Any]] = []
        for finding in findings:
            result = {
                "ruleId": finding.rule_id,
                "message": {"text": finding.description},
                "level": self._map_severity(finding.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file},
                        }
                    }
                ],
                "fingerprints": {"primaryLocationLineHash": finding.fingerprint},
            }
            results.append(result)

        # Build SARIF structure
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "kube-chainsaw",
                            "version": __version__,
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def _map_severity(self, severity: Severity) -> str:
        """Map Severity enum to SARIF level.

        Args:
            severity: Finding severity.

        Returns:
            SARIF level string (error, warning, note, none).
        """
        if severity == Severity.CRITICAL or severity == Severity.HIGH:
            return "error"
        elif severity == Severity.WARNING:
            return "warning"
        else:  # INFO
            return "note"
