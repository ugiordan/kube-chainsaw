"""Tests for kube_chainsaw.models."""

import pytest

from kube_chainsaw.models import (
    AnalyzerError,
    BindingScope,
    Finding,
    LoadedResources,
    Severity,
)


class TestSeverity:
    """Test Severity enum."""

    def test_severity_ordering(self):
        """Severity levels should be ordered: INFO < WARNING < HIGH < CRITICAL."""
        assert Severity.INFO < Severity.WARNING
        assert Severity.WARNING < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL
        assert Severity.INFO == 0
        assert Severity.WARNING == 1
        assert Severity.HIGH == 2
        assert Severity.CRITICAL == 3

    def test_from_str_case_insensitive(self):
        """from_str should accept case-insensitive strings."""
        assert Severity.from_str("info") == Severity.INFO
        assert Severity.from_str("INFO") == Severity.INFO
        assert Severity.from_str("InFo") == Severity.INFO
        assert Severity.from_str("warning") == Severity.WARNING
        assert Severity.from_str("WARNING") == Severity.WARNING
        assert Severity.from_str("high") == Severity.HIGH
        assert Severity.from_str("HIGH") == Severity.HIGH
        assert Severity.from_str("critical") == Severity.CRITICAL
        assert Severity.from_str("CRITICAL") == Severity.CRITICAL

    def test_from_str_invalid_raises(self):
        """from_str should raise ValueError for invalid input."""
        with pytest.raises(ValueError, match="Invalid severity"):
            Severity.from_str("invalid")
        with pytest.raises(ValueError, match="Invalid severity"):
            Severity.from_str("medium")
        with pytest.raises(ValueError, match="Invalid severity"):
            Severity.from_str("")


class TestFinding:
    """Test Finding dataclass."""

    def test_fingerprint_auto_computed(self):
        """Fingerprint should be auto-computed in __post_init__."""
        finding = Finding(
            rule_id="KC-001",
            severity=Severity.HIGH,
            title="Test Finding",
            file="test.yaml",
            description="Test description",
            remediation="Test remediation",
            resource_kind="ClusterRole",
            resource_name="admin",
        )
        assert finding.fingerprint != ""
        assert len(finding.fingerprint) == 64
        assert all(c in "0123456789abcdef" for c in finding.fingerprint)

    def test_fingerprint_deterministic(self):
        """Fingerprint should be deterministic for same inputs."""
        finding1 = Finding(
            rule_id="KC-001",
            severity=Severity.HIGH,
            title="Test Finding",
            file="test.yaml",
            description="Test description",
            remediation="Test remediation",
            resource_kind="ClusterRole",
            resource_name="admin",
        )
        finding2 = Finding(
            rule_id="KC-001",
            severity=Severity.HIGH,
            title="Test Finding",
            file="test.yaml",
            description="Test description",
            remediation="Test remediation",
            resource_kind="ClusterRole",
            resource_name="admin",
        )
        assert finding1.fingerprint == finding2.fingerprint

    def test_fingerprint_differs_by_namespace(self):
        """Fingerprint should differ when namespace differs."""
        finding1 = Finding(
            rule_id="KC-001",
            severity=Severity.HIGH,
            title="Test Finding",
            file="test.yaml",
            description="Test description",
            remediation="Test remediation",
            resource_kind="Role",
            resource_name="admin",
            resource_namespace="default",
        )
        finding2 = Finding(
            rule_id="KC-001",
            severity=Severity.HIGH,
            title="Test Finding",
            file="test.yaml",
            description="Test description",
            remediation="Test remediation",
            resource_kind="Role",
            resource_name="admin",
            resource_namespace="kube-system",
        )
        assert finding1.fingerprint != finding2.fingerprint

    def test_fingerprint_pipe_delimiter_prevents_collision(self):
        """Pipe delimiter should prevent field collision."""
        # KC-001|ClusterRole|admin vs KC-001|ClusterRolead|min
        finding1 = Finding(
            rule_id="KC-001",
            severity=Severity.HIGH,
            title="Test Finding",
            file="test.yaml",
            description="Test description",
            remediation="Test remediation",
            resource_kind="ClusterRole",
            resource_name="admin",
        )
        finding2 = Finding(
            rule_id="KC-001",
            severity=Severity.HIGH,
            title="Test Finding",
            file="test.yaml",
            description="Test description",
            remediation="Test remediation",
            resource_kind="ClusterRolead",
            resource_name="min",
        )
        assert finding1.fingerprint != finding2.fingerprint

    def test_finding_defaults(self):
        """Finding should have correct default values."""
        finding = Finding(
            rule_id="KC-001",
            severity=Severity.HIGH,
            title="Test Finding",
            file="test.yaml",
            description="Test description",
            remediation="Test remediation",
            resource_kind="ClusterRole",
            resource_name="admin",
        )
        assert finding.resource_namespace is None
        assert finding.suppressed is False


class TestLoadedResources:
    """Test LoadedResources dataclass."""

    def test_is_empty_when_empty(self):
        """is_empty should return True when all collections are empty."""
        resources = LoadedResources()
        assert resources.is_empty() is True

    def test_is_empty_with_cluster_roles(self):
        """is_empty should return False when cluster_roles is not empty."""
        resources = LoadedResources(cluster_roles={"test": {}})
        assert resources.is_empty() is False

    def test_is_empty_with_roles(self):
        """is_empty should return False when roles is not empty."""
        resources = LoadedResources(roles={"test": {}})
        assert resources.is_empty() is False

    def test_is_empty_with_cluster_role_bindings(self):
        """is_empty should return False when cluster_role_bindings is not empty."""
        resources = LoadedResources(cluster_role_bindings=[{"test": "binding"}])
        assert resources.is_empty() is False

    def test_is_empty_with_role_bindings(self):
        """is_empty should return False when role_bindings is not empty."""
        resources = LoadedResources(role_bindings=[{"test": "binding"}])
        assert resources.is_empty() is False

    def test_is_empty_with_service_accounts(self):
        """is_empty should return False when service_accounts is not empty."""
        resources = LoadedResources(service_accounts={"test": {}})
        assert resources.is_empty() is False

    def test_is_empty_with_pods(self):
        """is_empty should return False when pods is not empty."""
        resources = LoadedResources(pods={"test": {}})
        assert resources.is_empty() is False


class TestAnalyzerError:
    """Test AnalyzerError exception."""

    def test_analyzer_error_is_exception(self):
        """AnalyzerError should be an Exception."""
        assert issubclass(AnalyzerError, Exception)

    def test_analyzer_error_can_be_raised(self):
        """AnalyzerError should be raisable with a message."""
        with pytest.raises(AnalyzerError, match="Test error"):
            raise AnalyzerError("Test error")


class TestBindingScope:
    """Test BindingScope dataclass."""

    def test_binding_scope_defaults(self):
        """BindingScope should have correct default values."""
        scope = BindingScope()
        assert scope.cluster_wide is False
        assert scope.namespace_scoped is False
        assert scope.unbound is False
        assert scope.cluster_bindings == []
        assert scope.role_bindings == []
        assert scope.subject_types == {}
