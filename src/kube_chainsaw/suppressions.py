"""Suppression mechanism for kube-chainsaw findings."""

import yaml
from pathlib import Path
from typing import List
from kube_chainsaw.models import Finding


def load_suppressions(path: str) -> List[dict]:
    """Load suppressions from a YAML file.

    Args:
        path: Path to suppression YAML file.

    Returns:
        List of suppression dictionaries.

    Raises:
        FileNotFoundError: If the suppression file doesn't exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Suppression file not found: {path}")

    data = yaml.safe_load(p.read_text())
    if not data or "suppressions" not in data:
        return []

    return data["suppressions"]


def apply_suppressions(findings: List[Finding], suppressions: List[dict]) -> None:
    """Apply suppressions to findings, marking matching findings as suppressed.

    Findings are NOT removed from the list, just marked with suppressed=True.

    Matching rules:
    - rule_id must match exactly
    - resource_name must match exactly
    - If resource_namespace is specified in suppression, it must match exactly
    - If resource_namespace is omitted in suppression, matches ALL namespaces (wildcard)

    Args:
        findings: List of findings to apply suppressions to (modified in place).
        suppressions: List of suppression rules from load_suppressions().
    """
    for finding in findings:
        for supp in suppressions:
            # Check rule_id match
            if finding.rule_id != supp.get("rule_id"):
                continue

            # Check resource_name match
            if finding.resource_name != supp.get("resource_name"):
                continue

            # Check namespace match (if specified in suppression)
            supp_ns = supp.get("resource_namespace")
            if supp_ns is not None and finding.resource_namespace != supp_ns:
                continue

            # All conditions match, mark as suppressed and stop checking this finding
            finding.suppressed = True
            break
