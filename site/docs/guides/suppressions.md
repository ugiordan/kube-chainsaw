# Suppressions

Suppressions allow you to mark specific findings as accepted risks or false positives without modifying the manifests.

---

## Suppression File Format

Create `suppressions.yaml` in your project root:

```yaml
suppressions:
- rule_id: KC-001
  resource_name: admin-cluster-role
  reason: "Required for cluster operator"

- rule_id: KC-004
  resource_name: default
  resource_namespace: kube-system
  reason: "kube-system default SA needs elevated permissions"
```

---

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `rule_id` | Yes | Rule to suppress (e.g., KC-001) |
| `resource_name` | Yes | Resource name to match (exact match) |
| `resource_namespace` | No | Namespace to match (omit for cluster-scoped or wildcard) |
| `reason` | No | Why this finding is suppressed (for documentation) |

---

## Matching Logic

A suppression matches a finding if **all** specified fields match:

- `rule_id` must match exactly
- `resource_name` must match exactly
- If `resource_namespace` is specified, it must match exactly; if omitted, acts as a wildcard (matches any namespace or cluster-scoped resources)

**Example 1:** Suppress KC-001 for a specific ClusterRole:

```yaml
suppressions:
- rule_id: KC-001
  resource_name: admin-role
  reason: "Admin role requires wildcard verbs"
```

**Example 2:** Suppress KC-004 for default ServiceAccount in kube-system:

```yaml
suppressions:
- rule_id: KC-004
  resource_name: default
  resource_namespace: kube-system
  reason: "System namespace uses default ServiceAccounts"
```

**Example 3:** Suppress KC-014 for all RoleBindings named "viewer-binding" in any namespace:

```yaml
suppressions:
- rule_id: KC-014
  resource_name: viewer-binding
  reason: "Standard pattern across all namespaces"
```

---

## Suppression Validation

kube-chainsaw validates suppressions at load time:

- `rule_id` must be non-empty
- `resource_name` must be non-empty
- If `rule_id` doesn't match the known pattern (KC-001 through KC-015), a warning is printed to stderr

Unrecognized `rule_id` values (e.g., typos or custom rules) generate warnings but don't fail the scan.

---

## Using Suppressions in CI

Commit the suppression file to version control:

```bash
git add suppressions.yaml
git commit -m "Suppress known RBAC findings"
```

Reference it in CI:

```bash
kube-chainsaw k8s/ --suppressions suppressions.yaml
```

---

## Suppressed Findings in Output

Suppressed findings are included in the output but marked with `[SUPPRESSED]`:

```
=== HIGH ===

  [KC-001] Wildcard resource access [SUPPRESSED]
    File:        k8s/admin-role.yaml
    Resource:    ClusterRole/admin-role
    ...
```

Suppressed findings do not count toward the exit code threshold.

---

## Best Practices

1. **Always provide reason**: Future maintainers need to understand why findings are suppressed
2. **Scope suppressions narrowly**: Match specific resources with explicit namespace when possible
3. **Review suppressions regularly**: Audit the suppression file during security reviews
4. **Commit suppressions to version control**: Track changes and provide accountability

---

## Examples

### Suppress admin role findings:

```yaml
suppressions:
- rule_id: KC-001
  resource_name: cluster-admin-role
  reason: "Required for Kubernetes cluster operator"

- rule_id: KC-010
  resource_name: cluster-admin-role
  reason: "Required for Kubernetes cluster operator"
```

### Suppress cluster-admin pod in specific namespace:

```yaml
suppressions:
- rule_id: KC-013
  resource_name: operator-deployment
  resource_namespace: operators
  reason: "Operator requires cluster-admin for CRD management"
```

### Suppress RoleBinding to ClusterRole pattern:

```yaml
suppressions:
- rule_id: KC-014
  resource_name: read-pods-binding
  resource_namespace: monitoring
  reason: "Standard read-only pattern for monitoring"
```

---

## Next Steps

- [Understanding Findings](findings.md): Learn what each severity level means
- [CLI Reference](../reference/cli.md): All command-line options
- [Detection Rules](../reference/rules.md): Full rule descriptions
