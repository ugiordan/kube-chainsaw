# Adding Detection Rules

Learn how to add new detection rules to kube-chainsaw.

---

## Rule Structure

Each rule is a Python class that implements the `Rule` interface:

```python
from kube_chainsaw.rules.base import Rule
from kube_chainsaw.models import Finding, SeverityLevel, RuleContext

class MyCustomRule(Rule):
    rule_id = "KC-016"
    severity = SeverityLevel.HIGH
    name = "MyCustomRule"
    description = "Brief description of what this rule detects"
    
    def check(self, context: RuleContext) -> list[Finding]:
        findings = []
        
        # Analyze resources in context
        for role in context.roles:
            if self._is_violation(role):
                findings.append(self._create_finding(role))
        
        return findings
    
    def _is_violation(self, role) -> bool:
        # Detection logic
        pass
    
    def _create_finding(self, role) -> Finding:
        # Create Finding object
        pass
```

---

## RuleContext

The `RuleContext` object provides access to all parsed RBAC resources:

```python
class RuleContext:
    roles: list[Role]                    # All Roles
    cluster_roles: list[ClusterRole]     # All ClusterRoles
    role_bindings: list[RoleBinding]     # All RoleBindings
    cluster_role_bindings: list[ClusterRoleBinding]
    service_accounts: list[ServiceAccount]
    graph: RBACGraph                     # Permission graph
```

---

## Example: Simple Pattern Rule

Detect Roles with `create` verb on `pods/eviction`:

```python
from kube_chainsaw.rules.base import Rule
from kube_chainsaw.models import Finding, SeverityLevel, RuleContext

class PodEvictionRule(Rule):
    rule_id = "KC-016"
    severity = SeverityLevel.MEDIUM
    name = "PodEviction"
    description = "Detects create permission on pods/eviction subresource"
    
    def check(self, context: RuleContext) -> list[Finding]:
        findings = []
        
        all_roles = context.roles + context.cluster_roles
        
        for role in all_roles:
            for rule in role.rules:
                if "pods/eviction" in rule.resources and "create" in rule.verbs:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Pod eviction permission in {role.kind} '{role.metadata.name}'",
                        impact="Allows eviction of pods, potentially disrupting workloads",
                        recommendation="Restrict pods/eviction to cluster administrators",
                        location=role.location,
                        resource=role.to_resource_ref()
                    ))
        
        return findings
```

---

## Example: Graph Traversal Rule

Detect ServiceAccounts with indirect access to cluster-scoped resources:

```python
from kube_chainsaw.rules.base import Rule
from kube_chainsaw.models import Finding, SeverityLevel, RuleContext

class IndirectClusterAccessRule(Rule):
    rule_id = "KC-017"
    severity = SeverityLevel.HIGH
    name = "IndirectClusterAccess"
    description = "Detects ServiceAccounts with indirect access to cluster-scoped resources"
    
    def check(self, context: RuleContext) -> list[Finding]:
        findings = []
        
        for sa in context.service_accounts:
            # Use graph to find all reachable permissions
            permissions = context.graph.get_permissions_for_service_account(sa)
            
            # Check if any permission grants cluster-scoped access
            cluster_scoped = [p for p in permissions if p.scope == "cluster"]
            
            if cluster_scoped and sa.namespace != "kube-system":
                # Find the path from SA to cluster-scoped resource
                path = context.graph.find_path(sa, cluster_scoped[0])
                
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"ServiceAccount '{sa.metadata.name}' has indirect cluster access",
                    impact=f"Can access cluster-scoped resources via {len(path)} hops",
                    recommendation="Restrict bindings or use namespace-scoped roles",
                    location=sa.location,
                    resource=sa.to_resource_ref(),
                    metadata={
                        "path": [str(node) for node in path],
                        "cluster_permissions": [str(p) for p in cluster_scoped]
                    }
                ))
        
        return findings
```

---

## Testing Rules

Create a test fixture in `tests/fixtures/`:

**tests/fixtures/kc016_pod_eviction.yaml:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-evictor
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]
```

Write a test in `tests/test_rules.py`:

```python
from kube_chainsaw.rules.kc016_pod_eviction import PodEvictionRule
from kube_chainsaw.scanner import Scanner

def test_pod_eviction_detection():
    scanner = Scanner()
    findings = scanner.scan_file("tests/fixtures/kc016_pod_eviction.yaml")
    
    # Filter to KC-016 findings
    kc016_findings = [f for f in findings if f.rule_id == "KC-016"]
    
    assert len(kc016_findings) == 1
    assert kc016_findings[0].resource.name == "pod-evictor"
    assert "eviction" in kc016_findings[0].message.lower()
```

Run the test:

```bash
pytest tests/test_rules.py::test_pod_eviction_detection
```

---

## Registering Rules

Add your rule to `kube_chainsaw/rules/__init__.py`:

```python
from .kc001_wildcard_verbs import WildcardVerbsRule
from .kc002_wildcard_resources import WildcardResourcesRule
# ... existing rules ...
from .kc016_pod_eviction import PodEvictionRule

ALL_RULES = [
    WildcardVerbsRule(),
    WildcardResourcesRule(),
    # ... existing rules ...
    PodEvictionRule(),
]
```

---

## Rule ID Conventions

- Core rules: `KC-001` through `KC-999`
- Plugin rules: `PLUGIN-XXX-001`
- Custom rules: `CUSTOM-001` or organization prefix (e.g., `ACME-001`)

---

## Severity Guidelines

| Severity | Use When |
|----------|----------|
| CRITICAL | Direct path to cluster-admin or privilege escalation chains |
| HIGH | Dangerous permissions or misconfigurations (wildcard verbs, secret access) |
| MEDIUM | Overly broad permissions or policy violations |
| LOW | Best practice violations or inefficiencies |

---

## Documentation

Add a rule description to `site/docs/reference/rules.md`:

```markdown
## KC-016: Pod Eviction Permission

**Severity:** MEDIUM

**Description:** Detects `create` verb on `pods/eviction` subresource.

**Impact:** Allows eviction of pods, potentially disrupting workloads.

**Example:**

...yaml
rules:
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]
...

**Recommendation:** Restrict `pods/eviction` to cluster administrators.
```

---

## Pull Request Checklist

Before submitting a PR:

- [ ] Rule class implements `Rule` interface
- [ ] Rule ID follows conventions (KC-XXX)
- [ ] Severity is appropriate
- [ ] Test fixture and test case added
- [ ] All tests pass (`pytest`)
- [ ] Code formatted (`black .`)
- [ ] Linting passes (`ruff check .`)
- [ ] Documentation added to `rules.md`

---

## Next Steps

- [Development Setup](setup.md): Set up local environment
- [Architecture](../architecture/overview.md): Understand the codebase
- [Detection Rules Reference](../reference/rules.md): See existing rules
