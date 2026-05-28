"""RBAC analyzer with 15 detection rules (KC-001 through KC-015)."""

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from .models import AnalyzerError, BindingScope, Finding, LoadedResources, Severity


# Dangerous verbs that indicate privilege escalation risk
DANGEROUS_VERBS: Dict[str, str] = {
    "*": "KC-002",
    "escalate": "KC-003",
    "impersonate": "KC-004",
    "bind": "KC-005",
}

# Dangerous resources that indicate access to sensitive data or control plane
DANGEROUS_RESOURCES: Dict[str, str] = {
    "*": "KC-001",
    "secrets": "KC-006",
    "pods/exec": "KC-007",
    "pods/attach": "KC-007",
    "nodes": "KC-008",
    "persistentvolumes": "KC-009",
    "clusterroles": "KC-010",
    "clusterrolebindings": "KC-010",
}

# Escalation combination: verbs X resources in the same rule
ESCALATION_COMBOS: List[Tuple[Set[str], Set[str], str]] = [
    (
        {"create", "patch", "update"},
        {"roles", "clusterroles", "rolebindings", "clusterrolebindings"},
        "KC-011",
    ),
    (
        {"create"},
        {"pods"},
        "KC-012",
    ),
]


class RBACAnalyzer:
    """Analyzes Kubernetes RBAC manifests for security issues.

    Usage:
        analyzer = RBACAnalyzer()
        analyzer.load(resources)
        findings = analyzer.analyze()
    """

    def __init__(self) -> None:
        self._resources: Optional[LoadedResources] = None
        self._findings: List[Finding] = []

    def load(self, resources: LoadedResources) -> None:
        """Load resources for analysis.

        Args:
            resources: Loaded Kubernetes resources from load_manifests().
        """
        self._resources = resources

    def analyze(self) -> List[Finding]:
        """Run all 15 detection rules and return findings.

        Returns:
            List of Finding objects, one per triggered rule per resource.

        Raises:
            AnalyzerError: If load() has not been called.
        """
        if self._resources is None:
            raise AnalyzerError("load() must be called before analyze()")

        self._findings = []

        # Analyze ClusterRoles for dangerous permissions (KC-001 through KC-012)
        self._analyze_cluster_roles()

        # Analyze Roles for dangerous permissions (same rules, severity capped)
        self._analyze_roles()

        # Check aggregated ClusterRoles (KC-015)
        self._check_aggregated_roles()

        # Analyze privilege chains: SA -> Pod mappings (KC-013, KC-014)
        self._analyze_privilege_chains()

        return self._findings

    # ------------------------------------------------------------------
    # Binding scope resolution
    # ------------------------------------------------------------------

    def _get_binding_scope(self, role_name: str) -> BindingScope:
        """Determine if a ClusterRole is bound cluster-wide or namespace-scoped.

        Checks both ClusterRoleBindings and RoleBindings that reference
        this ClusterRole by name.

        Args:
            role_name: Name of the ClusterRole.

        Returns:
            BindingScope with cluster_wide, namespace_scoped, unbound flags
            and subject type counts.
        """
        assert self._resources is not None

        cluster_bindings: List[str] = []
        for binding in self._resources.cluster_role_bindings:
            role_ref = binding["doc"].get("roleRef", {})
            if role_ref.get("name") == role_name:
                binding_name = binding["doc"].get("metadata", {}).get("name", "unknown")
                cluster_bindings.append(binding_name)

        role_bindings: List[str] = []
        for binding in self._resources.role_bindings:
            role_ref = binding["doc"].get("roleRef", {})
            if role_ref.get("name") == role_name and role_ref.get("kind") == "ClusterRole":
                binding_name = binding["doc"].get("metadata", {}).get("name", "unknown")
                role_bindings.append(binding_name)

        # Count subject types across all bindings referencing this ClusterRole
        subject_types: Dict[str, int] = {"ServiceAccount": 0, "Group": 0, "User": 0}
        for binding in self._resources.cluster_role_bindings + self._resources.role_bindings:
            role_ref = binding["doc"].get("roleRef", {})
            if role_ref.get("name") == role_name and role_ref.get("kind") == "ClusterRole":
                for subject in binding["doc"].get("subjects", []):
                    kind = subject.get("kind", "")
                    if kind in subject_types:
                        subject_types[kind] += 1

        return BindingScope(
            cluster_wide=len(cluster_bindings) > 0,
            namespace_scoped=len(role_bindings) > 0,
            unbound=len(cluster_bindings) == 0 and len(role_bindings) == 0,
            cluster_bindings=cluster_bindings,
            role_bindings=role_bindings,
            subject_types=subject_types,
        )

    # ------------------------------------------------------------------
    # Severity determination
    # ------------------------------------------------------------------

    def _determine_severity(
        self,
        binding_scope: BindingScope,
        has_wildcard: bool,
    ) -> Severity:
        """Determine finding severity based on binding scope and permissions.

        Severity ladder:
        - Unbound ClusterRole -> INFO
        - Namespace-scoped without wildcards -> WARNING
        - Namespace-scoped with wildcards -> HIGH
        - Cluster-wide without wildcards -> HIGH
        - Cluster-wide with wildcards -> CRITICAL

        When a ClusterRole has both ClusterRoleBindings AND RoleBindings,
        the cluster-wide scope takes precedence (highest scope wins).

        Args:
            binding_scope: Binding scope for the ClusterRole.
            has_wildcard: Whether the triggering rule contains wildcard
                          verbs or resources.

        Returns:
            Severity enum value.
        """
        if binding_scope.unbound:
            return Severity.INFO

        if binding_scope.cluster_wide:
            if has_wildcard:
                return Severity.CRITICAL
            return Severity.HIGH

        # namespace_scoped only
        if has_wildcard:
            return Severity.HIGH
        return Severity.WARNING

    # ------------------------------------------------------------------
    # ClusterRole analysis
    # ------------------------------------------------------------------

    def _analyze_cluster_roles(self) -> None:
        """Analyze ClusterRoles for dangerous verbs, resources, and escalation combos."""
        assert self._resources is not None

        for role_name, role_data in self._resources.cluster_roles.items():
            rules = role_data.get("rules", [])
            file_path = role_data.get("file", "")

            binding_scope = self._get_binding_scope(role_name)

            # Track which rule_ids have been triggered for this role
            # to avoid duplicate findings for the same rule_id on the same resource
            triggered_rule_ids: Set[str] = set()

            # Determine if any rule in this role has wildcards (for severity calc)
            has_any_wildcard = False
            for rule in rules:
                resources = [r.lower() for r in rule.get("resources", [])]
                verbs = [v.lower() for v in rule.get("verbs", [])]
                if "*" in resources or "*" in verbs:
                    has_any_wildcard = True
                    break

            for rule in rules:
                resources = [r.lower() for r in rule.get("resources", [])]
                verbs = [v.lower() for v in rule.get("verbs", [])]

                # Check dangerous verbs
                for verb in verbs:
                    rule_id = DANGEROUS_VERBS.get(verb)
                    if rule_id and rule_id not in triggered_rule_ids:
                        triggered_rule_ids.add(rule_id)
                        # Wildcard check: is this specific finding about a wildcard?
                        is_wildcard = verb == "*"
                        severity = self._determine_severity(binding_scope, has_any_wildcard or is_wildcard)
                        self._findings.append(Finding(
                            rule_id=rule_id,
                            severity=severity,
                            title=f"ClusterRole {role_name} has dangerous verb: {verb}",
                            file=file_path,
                            description=f"Verb '{verb}' in ClusterRole {role_name}",
                            remediation="Remove dangerous verb or scope to minimum required permissions",
                            resource_kind="ClusterRole",
                            resource_name=role_name,
                        ))

                # Check dangerous resources
                for resource in resources:
                    rule_id = DANGEROUS_RESOURCES.get(resource)
                    if rule_id and rule_id not in triggered_rule_ids:
                        triggered_rule_ids.add(rule_id)
                        is_wildcard = resource == "*"
                        severity = self._determine_severity(binding_scope, has_any_wildcard or is_wildcard)
                        self._findings.append(Finding(
                            rule_id=rule_id,
                            severity=severity,
                            title=f"ClusterRole {role_name} has dangerous resource: {resource}",
                            file=file_path,
                            description=f"Resource '{resource}' in ClusterRole {role_name}",
                            remediation="Remove dangerous resource access or scope to minimum required permissions",
                            resource_kind="ClusterRole",
                            resource_name=role_name,
                        ))

                # Check escalation combos (verb + resource in same rule)
                for esc_verbs, esc_resources, rule_id in ESCALATION_COMBOS:
                    if rule_id in triggered_rule_ids:
                        continue
                    # Both sets must have intersection in the SAME rule
                    if set(verbs) & esc_verbs and set(resources) & esc_resources:
                        triggered_rule_ids.add(rule_id)
                        severity = self._determine_severity(binding_scope, has_any_wildcard)
                        self._findings.append(Finding(
                            rule_id=rule_id,
                            severity=severity,
                            title=f"ClusterRole {role_name} has escalation combo",
                            file=file_path,
                            description=(
                                f"Escalation risk: verbs {sorted(set(verbs) & esc_verbs)} "
                                f"on resources {sorted(set(resources) & esc_resources)} "
                                f"in ClusterRole {role_name}"
                            ),
                            remediation="Remove escalation-enabling verb/resource combination",
                            resource_kind="ClusterRole",
                            resource_name=role_name,
                        ))

    # ------------------------------------------------------------------
    # Role analysis (namespace-scoped, severity capped at WARNING)
    # ------------------------------------------------------------------

    def _analyze_roles(self) -> None:
        """Analyze namespace-scoped Roles for dangerous permissions.

        Same detection rules as ClusterRoles, but severity is capped at WARNING.
        """
        assert self._resources is not None

        for role_key, role_data in self._resources.roles.items():
            rules = role_data.get("rules", [])
            file_path = role_data.get("file", "")

            # role_key format: "namespace/name"
            parts = role_key.split("/", 1)
            namespace = parts[0] if len(parts) > 1 else "default"
            role_name = parts[1] if len(parts) > 1 else parts[0]

            # Check if this Role is bound (has a RoleBinding referencing it)
            is_bound = False
            for binding in self._resources.role_bindings:
                role_ref = binding["doc"].get("roleRef", {})
                if role_ref.get("name") == role_name and role_ref.get("kind") == "Role":
                    bind_ns = binding["doc"].get("metadata", {}).get("namespace", "default")
                    if bind_ns == namespace:
                        is_bound = True
                        break

            triggered_rule_ids: Set[str] = set()

            for rule in rules:
                resources = [r.lower() for r in rule.get("resources", [])]
                verbs = [v.lower() for v in rule.get("verbs", [])]

                # Check dangerous verbs
                for verb in verbs:
                    rule_id = DANGEROUS_VERBS.get(verb)
                    if rule_id and rule_id not in triggered_rule_ids:
                        triggered_rule_ids.add(rule_id)
                        severity = Severity.WARNING if is_bound else Severity.INFO
                        self._findings.append(Finding(
                            rule_id=rule_id,
                            severity=severity,
                            title=f"Role {role_name} has dangerous verb: {verb}",
                            file=file_path,
                            description=f"Verb '{verb}' in Role {namespace}/{role_name}",
                            remediation="Remove dangerous verb or scope to minimum required permissions",
                            resource_kind="Role",
                            resource_name=role_name,
                            resource_namespace=namespace,
                        ))

                # Check dangerous resources
                for resource in resources:
                    rule_id = DANGEROUS_RESOURCES.get(resource)
                    if rule_id and rule_id not in triggered_rule_ids:
                        triggered_rule_ids.add(rule_id)
                        severity = Severity.WARNING if is_bound else Severity.INFO
                        self._findings.append(Finding(
                            rule_id=rule_id,
                            severity=severity,
                            title=f"Role {role_name} has dangerous resource: {resource}",
                            file=file_path,
                            description=f"Resource '{resource}' in Role {namespace}/{role_name}",
                            remediation="Remove dangerous resource access or scope to minimum required permissions",
                            resource_kind="Role",
                            resource_name=role_name,
                            resource_namespace=namespace,
                        ))

                # Check escalation combos
                for esc_verbs, esc_resources, rule_id in ESCALATION_COMBOS:
                    if rule_id in triggered_rule_ids:
                        continue
                    if set(verbs) & esc_verbs and set(resources) & esc_resources:
                        triggered_rule_ids.add(rule_id)
                        severity = Severity.WARNING if is_bound else Severity.INFO
                        self._findings.append(Finding(
                            rule_id=rule_id,
                            severity=severity,
                            title=f"Role {role_name} has escalation combo",
                            file=file_path,
                            description=(
                                f"Escalation risk: verbs {sorted(set(verbs) & esc_verbs)} "
                                f"on resources {sorted(set(resources) & esc_resources)} "
                                f"in Role {namespace}/{role_name}"
                            ),
                            remediation="Remove escalation-enabling verb/resource combination",
                            resource_kind="Role",
                            resource_name=role_name,
                            resource_namespace=namespace,
                        ))

    # ------------------------------------------------------------------
    # Aggregated ClusterRoles (KC-015)
    # ------------------------------------------------------------------

    def _check_aggregated_roles(self) -> None:
        """Detect aggregated ClusterRoles (KC-015), always INFO severity."""
        assert self._resources is not None

        for role_name, role_data in self._resources.cluster_roles.items():
            doc = role_data.get("doc", {})
            if "aggregationRule" in doc:
                selectors = doc["aggregationRule"].get("clusterRoleSelectors", [])
                self._findings.append(Finding(
                    rule_id="KC-015",
                    severity=Severity.INFO,
                    title=f"Aggregated ClusterRole detected: {role_name}",
                    file=role_data.get("file", ""),
                    description=f"Aggregates permissions from roles matching {selectors}",
                    remediation="Review aggregation selectors to ensure no unintended permissions are granted",
                    resource_kind="ClusterRole",
                    resource_name=role_name,
                ))

    # ------------------------------------------------------------------
    # Privilege chain analysis (KC-013, KC-014)
    # ------------------------------------------------------------------

    def _analyze_privilege_chains(self) -> None:
        """Build ClusterRole -> Binding -> SA -> Pod chains.

        KC-013: Pod with SA bound to cluster-admin.
        KC-014: RoleBinding (not ClusterRoleBinding) referencing a ClusterRole,
                where a Pod uses that SA.
        """
        assert self._resources is not None

        # Build SA -> permission mappings
        sa_permissions: Dict[str, List[dict]] = defaultdict(list)

        # From ClusterRoleBindings
        for binding in self._resources.cluster_role_bindings:
            doc = binding["doc"]
            role_ref = doc.get("roleRef", {})
            role_name = role_ref.get("name", "")
            for subject in doc.get("subjects", []):
                if subject.get("kind") == "ServiceAccount":
                    sa_ns = subject.get("namespace", "default")
                    sa_name = subject.get("name", "")
                    sa_key = f"{sa_ns}/{sa_name}"
                    sa_permissions[sa_key].append({
                        "type": "ClusterRoleBinding",
                        "role_kind": role_ref.get("kind", "ClusterRole"),
                        "role": role_name,
                        "binding": doc.get("metadata", {}).get("name", "unknown"),
                        "file": binding["file"],
                    })

        # From RoleBindings
        for binding in self._resources.role_bindings:
            doc = binding["doc"]
            role_ref = doc.get("roleRef", {})
            role_kind = role_ref.get("kind", "")
            role_name = role_ref.get("name", "")
            binding_ns = doc.get("metadata", {}).get("namespace", "default")
            for subject in doc.get("subjects", []):
                if subject.get("kind") == "ServiceAccount":
                    sa_ns = subject.get("namespace", binding_ns)
                    sa_name = subject.get("name", "")
                    sa_key = f"{sa_ns}/{sa_name}"
                    sa_permissions[sa_key].append({
                        "type": "RoleBinding",
                        "role_kind": role_kind,
                        "role": role_name,
                        "binding": doc.get("metadata", {}).get("name", "unknown"),
                        "file": binding["file"],
                    })

        # Track already-reported bindings for KC-014 dedup
        reported_bindings: Set[str] = set()

        # Map Pods to their SA permissions
        for pod_key, pod_info in self._resources.pods.items():
            namespace = pod_key.split("/")[0]
            pod_name = pod_key.split("/")[1] if "/" in pod_key else pod_key
            sa_name = pod_info.get("serviceAccount", "default")
            sa_key = f"{namespace}/{sa_name}"

            if sa_key not in sa_permissions:
                continue

            for perm in sa_permissions[sa_key]:
                role_name = perm["role"]

                # KC-013: Pod with cluster-admin
                if role_name == "cluster-admin":
                    self._findings.append(Finding(
                        rule_id="KC-013",
                        severity=Severity.CRITICAL,
                        title=f"Pod {pod_key} has cluster-admin access",
                        file=pod_info.get("file", ""),
                        description=(
                            f"Pod uses ServiceAccount {sa_key} bound to cluster-admin"
                        ),
                        remediation="Create a custom Role with minimal required permissions",
                        resource_kind="Pod",
                        resource_name=pod_name,
                        resource_namespace=namespace,
                    ))

                # KC-014: RoleBinding referencing a ClusterRole, where a Pod uses that SA
                if (
                    perm["type"] == "RoleBinding"
                    and perm["role_kind"] == "ClusterRole"
                    and perm["binding"] not in reported_bindings
                ):
                    reported_bindings.add(perm["binding"])
                    self._findings.append(Finding(
                        rule_id="KC-014",
                        severity=Severity.WARNING,
                        title=f"RoleBinding {perm['binding']} grants cluster-wide permissions",
                        file=perm["file"],
                        description=(
                            f"RoleBinding references ClusterRole {role_name}, "
                            f"granting cluster-scoped permissions in namespace scope"
                        ),
                        remediation="Use a namespace-scoped Role instead of ClusterRole",
                        resource_kind="Pod",
                        resource_name=pod_name,
                        resource_namespace=namespace,
                    ))
