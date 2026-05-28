# Suppressions

Suppressions allow you to mark specific findings as accepted risks or false positives without modifying the manifests.

---

## Suppression File Format

Create `.kube-chainsaw-suppressions.yaml` in your project root:

```yaml
- rule_id: KC-001
  resource_name: admin-cluster-role
  justification: "Required for cluster operator"
  expiry: "2027-06-01"

- rule_id: KC-004
  resource_name: default
  namespace: kube-system
  justification: "kube-system default SA needs elevated permissions"
  expiry: null  # No expiry

- rule_id: KC-007
  file_pattern: "test/**/*.yaml"
  justification: "Test manifests intentionally demonstrate escalation"
```

---

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `rule_id` | Yes | Rule to suppress (e.g., KC-001) |
| `resource_name` | No | Resource name to match (exact match) |
| `namespace` | No | Namespace to match |
| `file_pattern` | No | Glob pattern for file paths |
| `justification` | Yes | Why this finding is suppressed |
| `expiry` | No | ISO 8601 date when suppression expires (null = no expiry) |

---

## Matching Logic

A suppression matches a finding if **all** specified fields match:

- `rule_id` must match
- If `resource_name` is specified, it must match exactly
- If `namespace` is specified, it must match
- If `file_pattern` is specified, the file path must match the glob

**Example 1:** Suppress KC-001 for a specific role:

```yaml
- rule_id: KC-001
  resource_name: admin-role
  justification: "Admin role requires wildcard verbs"
```

**Example 2:** Suppress all KC-004 findings in kube-system:

```yaml
- rule_id: KC-004
  namespace: kube-system
  justification: "System namespace uses default ServiceAccounts"
```

**Example 3:** Suppress all findings in test files:

```yaml
- rule_id: "*"
  file_pattern: "test/**/*.yaml"
  justification: "Test fixtures"
```

---

## Expiry Dates

Suppressions can expire after a specified date:

```yaml
- rule_id: KC-003
  resource_name: temp-admin-binding
  justification: "Temporary access for incident response"
  expiry: "2027-01-15"
```

After `2027-01-15`, this suppression will no longer apply and the finding will reappear in scans.

Set `expiry: null` or omit the field for permanent suppressions.

---

## Using Suppressions in CI

Commit the suppression file to version control:

```bash
git add .kube-chainsaw-suppressions.yaml
git commit -m "Suppress known RBAC findings"
```

Reference it in CI:

```bash
kube-chainsaw scan k8s/ --suppressions .kube-chainsaw-suppressions.yaml
```

Or use the default file name (`.kube-chainsaw-suppressions.yaml` in the scan directory):

```bash
kube-chainsaw scan k8s/
```

---

## Multiple Suppression Files

You can specify multiple suppression files:

```bash
kube-chainsaw scan k8s/ --suppressions global.yaml,team-specific.yaml
```

Comma-separated file paths. Suppressions from all files are merged.

---

## Suppression Report

kube-chainsaw logs suppressed findings in verbose mode:

```bash
kube-chainsaw scan k8s/ --verbose
```

**Output:**

```
[INFO] Suppressed KC-001 for 'admin-role' (justification: Admin role requires wildcard verbs)
[INFO] Suppressed KC-004 for 'default' in kube-system (justification: System namespace)
```

---

## Best Practices

1. **Always provide justification**: Future maintainers need to understand why findings are suppressed
2. **Use expiry dates for temporary access**: Prevent suppressions from becoming permanent by default
3. **Scope suppressions narrowly**: Match specific resources instead of wildcard patterns when possible
4. **Review suppressions regularly**: Audit the suppression file during security reviews

---

## Examples

### Suppress admin role findings:

```yaml
- rule_id: KC-001
  resource_name: cluster-admin-role
  justification: "Required for Kubernetes cluster operator"
  expiry: null

- rule_id: KC-003
  resource_name: cluster-admin-binding
  justification: "Required for Kubernetes cluster operator"
  expiry: null
```

### Suppress findings in dev environment:

```yaml
- rule_id: "*"
  file_pattern: "k8s/dev/**/*.yaml"
  justification: "Dev environment has relaxed RBAC for debugging"
  expiry: "2027-12-31"
```

### Suppress specific escalation chain:

```yaml
- rule_id: KC-007
  resource_name: ci-pipeline-sa
  justification: "CI ServiceAccount needs pod exec for integration tests"
  expiry: "2027-06-01"
```

---

## Next Steps

- [Understanding Findings](findings.md): Learn what each severity level means
- [CLI Reference](../reference/cli.md): All command-line options
- [Detection Rules](../reference/rules.md): Full rule descriptions
