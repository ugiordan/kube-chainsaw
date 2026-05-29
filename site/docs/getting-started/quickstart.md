# Quick Start

Your first kube-chainsaw scan in 60 seconds.

---

## Step 1: Install

=== "Binary"

    ```bash
    # Linux (amd64)
    curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_linux_amd64.tar.gz | tar xz
    sudo mv kube-chainsaw /usr/local/bin/

    # macOS (Apple Silicon)
    curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_darwin_arm64.tar.gz | tar xz
    sudo mv kube-chainsaw /usr/local/bin/
    ```

=== "Go install"

    ```bash
    go install github.com/ugiordan/kube-chainsaw/cmd/kube-chainsaw@latest
    ```

=== "Docker"

    ```bash
    docker run --rm -v $(pwd):/scan ghcr.io/ugiordan/kube-chainsaw:latest /scan/config
    ```

---

## Step 2: Create Sample Manifests

Create a file `rbac.yaml` with a typical operator RBAC setup:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: my-operator-manager
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch", "create", "update"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterrolebindings", "clusterroles"]
    verbs: ["create", "patch", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: my-operator-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: my-operator-manager
subjects:
  - kind: ServiceAccount
    name: my-operator-sa
    namespace: operator-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-operator
  namespace: operator-system
spec:
  selector:
    matchLabels:
      app: my-operator
  template:
    metadata:
      labels:
        app: my-operator
    spec:
      serviceAccountName: my-operator-sa
      containers:
        - name: manager
          image: my-operator:latest
```

---

## Step 3: Scan

```bash
$ kube-chainsaw .
```

Output:

```
=== HIGH ===

  [KC-006] Secrets access
    File:        rbac.yaml
    Resource:    ClusterRole/my-operator-manager
    Description: Role "my-operator-manager" grants access to dangerous resource "secrets"
    Remediation: Restrict secrets access to specific namespaces and only the verbs needed

  [KC-010] RBAC modification capability
    File:        rbac.yaml
    Resource:    ClusterRole/my-operator-manager
    Description: Role "my-operator-manager" grants access to dangerous resource "clusterrolebindings"
    Remediation: Limit RBAC modification to dedicated admin roles with proper audit

  [KC-011] Privilege escalation via role/binding modification
    File:        rbac.yaml
    Resource:    ClusterRole/my-operator-manager
    Description: Role "my-operator-manager" can create/modify roles or bindings (privilege escalation risk)
    Remediation: Restrict ability to create/modify roles and bindings to admin users only

  [KC-012] Privilege escalation via workload creation
    File:        rbac.yaml
    Resource:    ClusterRole/my-operator-manager
    Description: Role "my-operator-manager" can create pods/workloads (privilege escalation risk)
    Remediation: Restrict workload creation to CI/CD pipelines and use PodSecurity admission

Total: 4 findings [4 HIGH]
```

kube-chainsaw found 4 issues: the operator has secrets access, can modify RBAC, and can create workloads, all cluster-wide. Each is a privilege escalation vector.

---

## Step 4: CI Integration

Fail the pipeline on CRITICAL or HIGH findings:

```bash
$ kube-chainsaw config/ --fail-on HIGH
# Exit code 1 if any HIGH+ finding exists
```

Generate SARIF for GitHub Code Scanning:

```bash
$ kube-chainsaw config/ --output results.sarif
# Writes SARIF to file, prints console to stdout
```

Use in GitHub Actions:

```yaml
- uses: ugiordan/kube-chainsaw@v1
  with:
    paths: config/ deploy/
    fail-on: HIGH
    format: sarif
    output: results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Step 5: Suppress Known Findings

If a finding is expected (e.g., the operator genuinely needs secrets access), create `suppressions.yaml`:

```yaml
suppressions:
  - rule_id: KC-006
    resource_name: my-operator-manager
    reason: "Operator manages TLS certificates stored as secrets"
```

```bash
$ kube-chainsaw config/ --suppressions suppressions.yaml
```

The finding is marked as suppressed in the output but still visible for audit trail. Suppressed findings don't affect the exit code.

---

## Step 6: JSON Output

For programmatic consumption:

```bash
$ kube-chainsaw config/ --format json
```

```json
{
  "findings": [
    {
      "rule_id": "KC-006",
      "severity": "HIGH",
      "title": "Secrets access",
      "file": "rbac.yaml",
      "description": "Role \"my-operator-manager\" grants access to dangerous resource \"secrets\"",
      "remediation": "Restrict secrets access to specific namespaces and only the verbs needed",
      "resource_kind": "ClusterRole",
      "resource_name": "my-operator-manager",
      "resource_namespace": "",
      "fingerprint": "a1b2c3d4...",
      "suppressed": false
    }
  ]
}
```

---

## Understanding Output

Each finding includes:

| Field | Description |
|-------|-------------|
| **Rule ID** | Detection rule (KC-001 through KC-015). See [Detection Rules](../reference/rules.md). |
| **Severity** | CRITICAL, HIGH, WARNING, or INFO |
| **File** | Path to the manifest file |
| **Resource** | Kubernetes resource kind and name |
| **Description** | What the misconfiguration is |
| **Remediation** | How to fix it |

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on` threshold (default: CRITICAL) |
| `1` | Findings at or above threshold |
| `2` | Runtime error (invalid arguments, file not found) |

---

## Next Steps

- [CI Integration](../guides/ci-integration.md): Automated security gates
- [Suppressions](../guides/suppressions.md): Suppress accepted risks
- [Detection Rules](../reference/rules.md): Full rule reference with YAML examples
- [CLI Reference](../reference/cli.md): All command-line options
