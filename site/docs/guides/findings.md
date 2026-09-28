# Understanding Findings

kube-chainsaw reports findings with severity levels, locations, impact descriptions, and actionable recommendations.

---

## Severity Levels

| Severity | Description | Examples |
|----------|-------------|----------|
| **CRITICAL** | Cluster-wide wildcard permissions or a workload bound to cluster-admin | KC-001, KC-002, KC-013 |
| **HIGH** | Cluster-wide dangerous access, privileged workload settings, or broad SCC assignments | KC-003, KC-006, KC-019, KC-024 |
| **WARNING** | Namespace-scoped risks, narrower workload settings, or broad NetworkPolicy peers | KC-014, KC-017, KC-021 |
| **INFO** | Unbound roles or findings requiring review rather than immediate remediation | KC-015 |

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

- **KC-001**, **KC-002**: Wildcard resources or verbs
- **KC-003** through **KC-005**: `escalate`, `impersonate`, or `bind`
- **KC-006**: Secrets access
- **KC-007**, **KC-008**: Dangerous pod subresources and node access
- **KC-009**, **KC-010**: PersistentVolume and RBAC modification access

### Privilege Escalation

Rules that detect multi-hop privilege escalation paths:

- **KC-011**: Role or binding modification combined with mutation verbs
- **KC-012**: Workload creation that can enable privilege escalation

### Privilege Chains and Aggregation

Rules that detect risky default configurations:

- **KC-013**: Workload using cluster-admin
- **KC-014**: RoleBinding referencing a ClusterRole
- **KC-015**: Aggregated ClusterRole

### Misconfigurations

Rules that detect configuration errors or inefficiencies:

- **KC-009**: Role/ClusterRole not bound to any subjects
- **KC-010**: Duplicate rules within a Role/ClusterRole
- **KC-011**: Empty or trivial roles
- **KC-016**: NetworkPolicy access
- **KC-017**, **KC-018**: Broad NetworkPolicy peers
- **KC-019** through **KC-022**: Dangerous workload security settings
- **KC-023**, **KC-024**: OpenShift SCC use and assignment
- **KC-025** through **KC-027**: declared external Service and route exposure
- **KC-028**, **KC-029**: credential-bearing and long-lived token Secrets
- **KC-030**, **KC-031**: ServiceAccount token minting and CSR approval/signing

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
| Privileged container | Bypass normal container isolation and access host-level capabilities |
| HostPath volume | Read or modify files, sockets, or runtime state on the node |
| Broad SCC assignment | Request privileged or host-integrated workloads as an overly broad identity |

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

### Example 2: Privileged Workload

**Finding:**

```
[HIGH] KC-019: Privileged container requested
  Recommendation: Remove privileged mode and use the narrowest securityContext required
```

**Fix:**

```yaml
# Before
securityContext:
  privileged: true

# After
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  runAsNonRoot: true
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
- **Operator patterns**: Infrastructure workloads may legitimately use host namespaces or hostPath (KC-020, KC-021)
- **OpenShift SCCs**: Built-in permissive SCCs are not reported unless directly assigned or granted through RBAC
- **NetworkPolicy intent**: Broad peers may be required for infrastructure or ingress controllers (KC-017, KC-018)
- **Declared exposure**: An external Service or Ingress may sit behind private network controls not visible in manifests (KC-025, KC-026, KC-027)
- **Secret workflows**: Some repositories intentionally use encrypted or generated Secret manifests; values are never printed by these checks (KC-028, KC-029)
- **Testing manifests**: Test fixtures may intentionally demonstrate bad patterns

Report false positives at [GitHub Issues](https://github.com/ugiordan/kube-chainsaw/issues) or suppress them locally.

---

## Next Steps

- [Detection Rules Reference](../reference/rules.md): Full descriptions of all 31 rules
- [Suppressions](suppressions.md): Suppress false positives or accepted risks
- [CLI Commands](../reference/cli.md): Control severity thresholds and output formats
