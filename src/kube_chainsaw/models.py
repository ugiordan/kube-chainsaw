"""Data models for kube-chainsaw."""

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional


class Severity(IntEnum):
    """Finding severity levels."""

    INFO = 0
    WARNING = 1
    HIGH = 2
    CRITICAL = 3

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        """Parse severity from case-insensitive string.

        Args:
            s: Severity string (info, warning, high, critical).

        Returns:
            Severity enum value.

        Raises:
            ValueError: If string is not a valid severity level.
        """
        try:
            return cls[s.upper()]
        except KeyError:
            raise ValueError(f"Invalid severity: {s}") from None


@dataclass
class Finding:
    """Security finding from analysis."""

    rule_id: str
    severity: Severity
    title: str
    file: str
    description: str
    remediation: str
    resource_kind: str
    resource_name: str
    resource_namespace: Optional[str] = None
    suppressed: bool = False
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """Compute fingerprint if not set."""
        if not self.fingerprint:
            fingerprint_input = (
                f"{self.rule_id}|{self.resource_kind}|{self.resource_name}|{self.resource_namespace or ''}"
            )
            self.fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()


@dataclass
class BindingScope:
    """Scope information for a subject's RBAC bindings."""

    cluster_wide: bool = False
    namespace_scoped: bool = False
    unbound: bool = False
    cluster_bindings: List[str] = field(default_factory=list)
    role_bindings: List[str] = field(default_factory=list)
    subject_types: Dict[str, int] = field(default_factory=dict)


@dataclass
class LoadedResources:
    """Container for loaded Kubernetes resources."""

    cluster_roles: Dict[str, dict] = field(default_factory=dict)
    roles: Dict[str, dict] = field(default_factory=dict)
    cluster_role_bindings: List[dict] = field(default_factory=list)
    role_bindings: List[dict] = field(default_factory=list)
    service_accounts: Dict[str, dict] = field(default_factory=dict)
    pods: Dict[str, dict] = field(default_factory=dict)

    def is_empty(self) -> bool:
        """Check if all resource collections are empty.

        Returns:
            True if no resources have been loaded.
        """
        return (
            not self.cluster_roles
            and not self.roles
            and not self.cluster_role_bindings
            and not self.role_bindings
            and not self.service_accounts
            and not self.pods
        )


class AnalyzerError(Exception):
    """Raised when trying to analyze before loading resources."""

    pass
