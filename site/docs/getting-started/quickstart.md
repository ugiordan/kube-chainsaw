# Quick Start

This guide walks through your first kube-chainsaw scan.

---

## Step 1: Install

```bash
curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_linux_amd64.tar.gz | tar xz
sudo mv kube-chainsaw /usr/local/bin/
```

Or use `go install`:

```bash
go install github.com/ugiordan/kube-chainsaw/cmd/kube-chainsaw@latest
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
kube-chainsaw test-manifests/
```

**Expected output:**

```
=== HIGH ===

  [KC-002] Wildcard verb access
    File:        test-manifests/role.yaml
    Resource:    ClusterRole/pod-reader
    Description: Role "pod-reader" has dangerous verb "*"
    Remediation: Replace wildcard (*) verbs with specific verbs needed

Total: 1 findings [1 HIGH]
```

---

## Step 4: Generate SARIF Output

For CI integration, generate SARIF:

```bash
kube-chainsaw test-manifests/ --format sarif --output results.sarif
```

The SARIF file can be uploaded to GitHub Code Scanning, GitLab SAST, or other security platforms. The tool writes SARIF to the file and prints a human-readable summary to stdout.

---

## Step 5: Suppress Known Findings

If a finding is intentional (e.g., admin role), create `suppressions.yaml`:

```yaml
suppressions:
- rule_id: KC-002
  resource_name: pod-reader
  reason: "Admin role requires wildcard verbs for operational flexibility"
```

Re-run the scan with suppressions:

```bash
kube-chainsaw test-manifests/ --suppressions suppressions.yaml
```

The KC-002 finding for `pod-reader` will now be marked as suppressed.

---

## Understanding the Output

Each finding includes:

- **Rule ID**: e.g., KC-001 (see [Detection Rules](../reference/rules.md))
- **Severity**: CRITICAL, HIGH, WARNING, INFO
- **File**: Path to the manifest file
- **Resource**: Kind and name of the resource
- **Description**: What the misconfiguration is
- **Remediation**: How to fix it

Exit codes:

- `0`: No findings at or above `--fail-on` threshold
- `1`: Findings at or above `--fail-on` threshold (default: CRITICAL)
- `2`: Runtime error (invalid arguments, file not found, etc.)

---

## Next Steps

- [CI Integration](../guides/ci-integration.md): Set up automated scans in GitHub Actions or GitLab CI
- [Suppressions Guide](../guides/suppressions.md): Learn suppression file syntax and best practices
- [Detection Rules](../reference/rules.md): Full reference of all 15 detection rules
- [CLI Commands](../reference/cli.md): Explore all command-line options
