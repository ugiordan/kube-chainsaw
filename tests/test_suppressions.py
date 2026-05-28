"""Tests for suppression mechanism."""

import pytest
import tempfile
from pathlib import Path
from kube_chainsaw.models import Finding, Severity
from kube_chainsaw.suppressions import load_suppressions, apply_suppressions


@pytest.fixture
def findings():
    """Sample findings for suppression tests."""
    return [
        Finding(
            rule_id="KC-006",
            severity=Severity.HIGH,
            title="Secrets",
            file="r.yaml",
            description="d",
            remediation="r",
            resource_kind="ClusterRole",
            resource_name="manager-role",
        ),
        Finding(
            rule_id="KC-011",
            severity=Severity.HIGH,
            title="Escalation",
            file="r.yaml",
            description="d",
            remediation="r",
            resource_kind="ClusterRole",
            resource_name="manager-role",
            resource_namespace="pipelines",
        ),
        Finding(
            rule_id="KC-001",
            severity=Severity.CRITICAL,
            title="Wildcards",
            file="r.yaml",
            description="d",
            remediation="r",
            resource_kind="ClusterRole",
            resource_name="admin",
        ),
    ]


def test_load_suppressions_valid_file():
    """load_suppressions loads valid YAML file with suppressions list."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""suppressions:
  - rule_id: KC-001
    resource_name: admin
  - rule_id: KC-006
    resource_name: manager-role
    resource_namespace: default
""")
        f.flush()
        path = f.name

    try:
        suppressions = load_suppressions(path)
        assert len(suppressions) == 2
        assert suppressions[0]["rule_id"] == "KC-001"
        assert suppressions[0]["resource_name"] == "admin"
        assert suppressions[1]["rule_id"] == "KC-006"
        assert suppressions[1]["resource_name"] == "manager-role"
        assert suppressions[1]["resource_namespace"] == "default"
    finally:
        Path(path).unlink()


def test_load_suppressions_file_not_found():
    """load_suppressions raises FileNotFoundError for nonexistent file."""
    with pytest.raises(FileNotFoundError, match="Suppression file not found"):
        load_suppressions("/nonexistent/path.yaml")


def test_load_suppressions_no_suppressions_key():
    """load_suppressions returns empty list for file without suppressions key."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("other_key: value\n")
        f.flush()
        path = f.name

    try:
        suppressions = load_suppressions(path)
        assert suppressions == []
    finally:
        Path(path).unlink()


def test_load_suppressions_empty_file():
    """load_suppressions returns empty list for empty YAML file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("")
        f.flush()
        path = f.name

    try:
        suppressions = load_suppressions(path)
        assert suppressions == []
    finally:
        Path(path).unlink()


def test_apply_suppressions_matching_finding(findings):
    """apply_suppressions marks matching finding as suppressed."""
    suppressions = [
        {"rule_id": "KC-001", "resource_name": "admin"}
    ]
    apply_suppressions(findings, suppressions)

    assert findings[0].suppressed is False  # KC-006
    assert findings[1].suppressed is False  # KC-011
    assert findings[2].suppressed is True   # KC-001 admin


def test_apply_suppressions_different_rule_id(findings):
    """apply_suppressions does NOT mark finding with different rule_id."""
    suppressions = [
        {"rule_id": "KC-999", "resource_name": "admin"}
    ]
    apply_suppressions(findings, suppressions)

    assert all(f.suppressed is False for f in findings)


def test_apply_suppressions_different_resource_name(findings):
    """apply_suppressions does NOT mark finding with different resource_name."""
    suppressions = [
        {"rule_id": "KC-001", "resource_name": "other-name"}
    ]
    apply_suppressions(findings, suppressions)

    assert all(f.suppressed is False for f in findings)


def test_apply_suppressions_namespace_match(findings):
    """Namespace-scoped suppression matches when resource_namespace matches."""
    suppressions = [
        {"rule_id": "KC-011", "resource_name": "manager-role", "resource_namespace": "pipelines"}
    ]
    apply_suppressions(findings, suppressions)

    assert findings[0].suppressed is False  # KC-006, no namespace
    assert findings[1].suppressed is True   # KC-011, namespace=pipelines
    assert findings[2].suppressed is False  # KC-001


def test_apply_suppressions_namespace_mismatch(findings):
    """Namespace-scoped suppression does NOT match when namespace differs."""
    suppressions = [
        {"rule_id": "KC-011", "resource_name": "manager-role", "resource_namespace": "default"}
    ]
    apply_suppressions(findings, suppressions)

    assert all(f.suppressed is False for f in findings)


def test_apply_suppressions_wildcard_namespace(findings):
    """Omitting resource_namespace in suppression matches ALL namespaces."""
    suppressions = [
        {"rule_id": "KC-006", "resource_name": "manager-role"}  # No namespace specified
    ]
    apply_suppressions(findings, suppressions)

    assert findings[0].suppressed is True   # KC-006, no namespace in finding
    assert findings[1].suppressed is False  # KC-011, different rule_id
    assert findings[2].suppressed is False  # KC-001


def test_suppressed_findings_remain_in_list(findings):
    """Suppressed findings remain in list, just marked suppressed=True."""
    initial_count = len(findings)
    suppressions = [
        {"rule_id": "KC-001", "resource_name": "admin"}
    ]
    apply_suppressions(findings, suppressions)

    assert len(findings) == initial_count
    assert findings[2].suppressed is True


def test_multiple_suppressions(findings):
    """Multiple suppressions can be applied."""
    suppressions = [
        {"rule_id": "KC-001", "resource_name": "admin"},
        {"rule_id": "KC-006", "resource_name": "manager-role"}
    ]
    apply_suppressions(findings, suppressions)

    assert findings[0].suppressed is True   # KC-006 manager-role
    assert findings[1].suppressed is False  # KC-011 (different rule_id)
    assert findings[2].suppressed is True   # KC-001 admin


def test_apply_suppressions_first_match_wins(findings):
    """First matching suppression wins (early break)."""
    suppressions = [
        {"rule_id": "KC-001", "resource_name": "admin"},
        {"rule_id": "KC-001", "resource_name": "admin"}  # Duplicate
    ]
    apply_suppressions(findings, suppressions)

    assert findings[2].suppressed is True
