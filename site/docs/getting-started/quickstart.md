# Quick Start

This guide walks through your first kube-chainsaw scan.

---

## Step 1: Install

```bash
pip install kube-chainsaw
```

---

## Step 2: Prepare Test Manifests

Create a directory with sample Kubernetes RBAC manifests:

```bash
mkdir test-manifests
cd test-manifests
```

Create `test-manifests/role.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["*"]  # Wildcard verbs
```

Create `test-manifests/binding.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-pods-global
subjects:
- kind: ServiceAccount
  name: default  # Binding to default SA
  namespace: default
roleRef:
  kind: ClusterRole
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

---

## Step 3: Run Your First Scan

Scan the directory:

```bash
kube-chainsaw scan test-manifests/
```

**Expected output:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 kube-chainsaw scan results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[HIGH] KC-001: Wildcard verbs in ClusterRole 'pod-reader'
  Location: test-manifests/role.yaml:7:11
  Impact: Grants create, delete, patch, and escalate permissions
  Recommendation: Replace '*' with explicit verbs: ['get', 'list', 'watch']

[HIGH] KC-004: Default ServiceAccount with elevated permissions
  Location: test-manifests/binding.yaml:8:9
  Impact: 'default' ServiceAccount can read all pods cluster-wide
  Recommendation: Create a dedicated ServiceAccount for this role

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 2 findings (0 critical, 2 high, 0 medium, 0 low)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Exit code: 1 (findings with severity >= high)
```

---

## Step 4: Generate SARIF Output

For CI integration, generate SARIF:

```bash
kube-chainsaw scan test-manifests/ --format sarif -o results.sarif
```

The SARIF file can be uploaded to GitHub Code Scanning, GitLab SAST, or other security platforms.

---

## Step 5: Suppress Known Findings

If a finding is intentional (e.g., admin role), create `.kube-chainsaw-suppressions.yaml`:

```yaml
- rule_id: KC-001
  resource_name: pod-reader
  justification: "Admin role requires wildcard verbs for operational flexibility"
  expiry: "2027-01-01"
```

Re-run the scan:

```bash
kube-chainsaw scan test-manifests/
```

The KC-001 finding for `pod-reader` will now be suppressed.

---

## Understanding the Output

Each finding includes:

- **Rule ID**: e.g., KC-001 (see [Detection Rules](../reference/rules.md))
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW
- **Location**: File path and line number
- **Impact**: What the misconfiguration allows
- **Recommendation**: How to fix it

Exit codes:

- `0`: No findings
- `1`: Findings at or above `--fail-on-severity` threshold (default: high)
- `2`: Scan error (invalid manifests, file not found, etc.)

---

## Next Steps

- [CI Integration](../guides/ci-integration.md): Set up automated scans in GitHub Actions or GitLab CI
- [Suppressions Guide](../guides/suppressions.md): Learn suppression file syntax and best practices
- [Detection Rules](../reference/rules.md): Full reference of all 15 detection rules
- [CLI Commands](../reference/cli.md): Explore all command-line options
