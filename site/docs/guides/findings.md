# Understanding Findings

kube-chainsaw reports findings with severity levels, locations, impact descriptions, and actionable recommendations.

---

## Severity Levels

| Severity | Description | Examples |
|----------|-------------|----------|
| **CRITICAL** | Privilege escalation chains that grant cluster-admin access | KC-007, KC-008 |
| **HIGH** | Dangerous permissions or misconfigurations that enable lateral movement | KC-001, KC-002, KC-003, KC-004 |
| **MEDIUM** | Overly broad permissions or potential security gaps | KC-005, KC-009, KC-010 |
| **LOW** | Best practice violations or inefficiencies | KC-011, KC-013, KC-014 |

---

## Finding Structure

Each finding includes:

```
[SEVERITY] RULE_ID: Description
  Location: file.yaml:line:column
  Impact: What this misconfiguration allows
  Recommendation: How to fix it
  [Additional context based on rule type]
```

**Example:**

```
[HIGH] KC-001: Wildcard verbs in ClusterRole 'pod-manager'
  Location: roles/admin.yaml:15:11
  Impact: Grants create, delete, patch, and escalate permissions on pods
  Recommendation: Replace '*' with explicit verbs: ['get', 'list', 'watch']
  ServiceAccounts bound: admin-sa (via admin-binding)
```

---

## Rule Categories

### Dangerous Permissions

Rules that detect overly broad or risky permissions:

- **KC-001**: Wildcard verbs (`verbs: ["*"]`)
- **KC-002**: Wildcard resources (`resources: ["*"]`)
- **KC-003**: Cluster-admin ClusterRoleBindings
- **KC-006**: Wildcard API groups

### Privilege Escalation

Rules that detect multi-hop privilege escalation paths:

- **KC-007**: Privilege escalation chains (e.g., `pods/exec` → secret access)
- **KC-008**: ServiceAccount token escalation paths

### Supply Chain Risks

Rules that detect risky default configurations:

- **KC-004**: Default ServiceAccount with elevated permissions
- **KC-005**: Bindings to system ServiceAccounts

### Misconfigurations

Rules that detect configuration errors or inefficiencies:

- **KC-009**: Role/ClusterRole not bound to any subjects
- **KC-010**: Duplicate rules within a Role/ClusterRole
- **KC-011**: Empty or trivial roles
- **KC-013**: Cross-namespace bindings without clear justification

---

## Interpreting Impact

The **Impact** field explains what an attacker or malicious pod could do if the misconfiguration is exploited.

**Examples:**

| Finding | Impact |
|---------|--------|
| Wildcard verbs on pods | Create, delete, and exec into any pod in the namespace |
| `pods/exec` permission | Gain shell access to running containers |
| Secret read access | Exfiltrate credentials, tokens, and sensitive data |
| Privilege escalation chain | Escalate from low-privilege SA to cluster-admin |

---

## Acting on Recommendations

kube-chainsaw provides specific, actionable recommendations:

### Example 1: Wildcard Verbs

**Finding:**

```
[HIGH] KC-001: Wildcard verbs in ClusterRole 'viewer-role'
  Recommendation: Replace '*' with explicit verbs: ['get', 'list', 'watch']
```

**Fix:**

```yaml
# Before
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["*"]

# After
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

### Example 2: Default ServiceAccount

**Finding:**

```
[HIGH] KC-004: Default ServiceAccount with elevated permissions
  Recommendation: Create a dedicated ServiceAccount for this role
```

**Fix:**

```yaml
# Create a new ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pod-reader-sa
  namespace: default
---
# Update the RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
subjects:
- kind: ServiceAccount
  name: pod-reader-sa  # Changed from 'default'
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

---

## When to Suppress

Some findings are intentional and should be suppressed rather than fixed:

- **Admin roles**: Cluster operators legitimately need broad permissions
- **CI/CD ServiceAccounts**: Automation accounts may require elevated access
- **Testing environments**: Non-production clusters may have relaxed RBAC

Use the [Suppressions Guide](suppressions.md) to suppress accepted risks.

---

## False Positives

kube-chainsaw prioritizes accuracy, but false positives can occur:

- **Cross-namespace dependencies**: Some legitimate use cases require cross-namespace bindings (KC-013)
- **Operator patterns**: Operators may use ServiceAccount token projection (KC-008)
- **Testing manifests**: Test fixtures may intentionally demonstrate bad patterns

Report false positives at [GitHub Issues](https://github.com/ugiordan/kube-chainsaw/issues) or suppress them locally.

---

## Next Steps

- [Detection Rules Reference](../reference/rules.md): Full descriptions of all 15 rules
- [Suppressions](suppressions.md): Suppress false positives or accepted risks
- [CLI Commands](../reference/cli.md): Control severity thresholds and output formats
