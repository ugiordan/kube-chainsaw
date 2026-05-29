# Output Formats

kube-chainsaw supports three output formats: console, JSON, and SARIF.

---

## Console (Default)

Human-readable output grouped by severity (CRITICAL first, INFO last).

**Usage:**

```bash
kube-chainsaw k8s/
```

**Example output:**

```
=== CRITICAL ===

  [KC-013] Pod running with cluster-admin privileges
    File:        k8s/deployment.yaml
    Resource:    default/Deployment/admin-deployment
    Description: Deployment "admin-deployment" uses ServiceAccount "admin-sa" which is bound to cluster-admin via ClusterRoleBinding "admin-binding"
    Remediation: Never use cluster-admin for pod service accounts; create a scoped role

=== HIGH ===

  [KC-001] Wildcard resource access
    File:        k8s/roles.yaml
    Resource:    ClusterRole/pod-manager
    Description: Role "pod-manager" uses wildcard apiGroups, granting access to all API groups including CRDs
    Remediation: Replace wildcard (*) resources with explicit resource names

Total: 2 findings [1 CRITICAL, 1 HIGH]
```

Findings are sorted by severity, then by rule ID within each severity group.

---

## JSON

Machine-readable JSON output for custom integrations.

**Usage:**

```bash
kube-chainsaw k8s/ --format json --output results.json
```

**Example output:**

```json
{
  "findings": [
    {
      "rule_id": "KC-001",
      "severity": "HIGH",
      "title": "Wildcard resource access",
      "file": "k8s/roles.yaml",
      "description": "Role \"pod-manager\" uses wildcard apiGroups, granting access to all API groups including CRDs",
      "remediation": "Replace wildcard (*) resources with explicit resource names",
      "resource_kind": "ClusterRole",
      "resource_name": "pod-manager",
      "resource_namespace": "",
      "fingerprint": "a3f2e1b...",
      "suppressed": false
    }
  ]
}
```

**Fields:**

- `rule_id`: Rule identifier (KC-001 through KC-015)
- `severity`: CRITICAL, HIGH, WARNING, INFO
- `title`: Short description of the rule
- `file`: Path to the manifest file
- `description`: Detailed description of the finding
- `remediation`: How to fix the issue
- `resource_kind`: Kind of the resource (ClusterRole, Role, etc.)
- `resource_name`: Name of the resource
- `resource_namespace`: Namespace (empty for cluster-scoped resources)
- `fingerprint`: SHA256 hash for deduplication
- `suppressed`: Whether the finding is suppressed

---

## SARIF

Static Analysis Results Interchange Format (SARIF) for GitHub Code Scanning, GitLab SAST, and other security platforms.

**Usage:**

```bash
kube-chainsaw k8s/ --format sarif --output results.sarif
```

**Example output:**

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "kube-chainsaw",
          "version": "1.0.0",
          "informationUri": "https://github.com/ugiordan/kube-chainsaw",
          "rules": [
            {
              "id": "KC-001",
              "shortDescription": {
                "text": "Wildcard resource access"
              },
              "help": {
                "text": "Replace wildcard (*) resources with explicit resource names"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "KC-001",
          "level": "error",
          "message": {
            "text": "Role \"pod-manager\" uses wildcard apiGroups, granting access to all API groups including CRDs"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "k8s/roles.yaml"
                }
              },
              "message": {
                "text": "ClusterRole/pod-manager"
              }
            }
          ],
          "partialFingerprints": {
            "kube-chainsaw/v1": "a3f2e1b..."
          }
        }
      ]
    }
  ]
}
```

**SARIF Features:**

- **Fingerprints**: Stable identifiers (SHA256) for deduplication across scans
- **SARIF level mapping**: CRITICAL/HIGH → `error`, WARNING → `warning`, INFO → `note`
- **Suppressions**: Suppressed findings are marked with `suppression` kind `inSource`

---

## Dual Output Mode

When using `--output`, kube-chainsaw writes to a file and prints to stdout:

```bash
kube-chainsaw k8s/ --output results.json
```

**Behavior:**

- `results.json`: JSON output
- `stdout`: Console format (unless `--quiet`)

Specify different formats for file and stdout:

```bash
kube-chainsaw k8s/ --format console --output results.sarif --output-format sarif
```

This writes SARIF to the file and prints console output to stdout.

---

## GitHub Code Scanning Integration

Upload SARIF to GitHub Code Scanning:

```yaml
- name: Run kube-chainsaw
  run: kube-chainsaw k8s/ --format sarif --output kube-chainsaw.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: kube-chainsaw.sarif
```

GitHub will display findings as code annotations in pull requests and the Security tab.

---

## GitLab SAST Integration

GitLab expects SARIF artifacts in the `sast` report type:

```yaml
rbac-scan:
  script:
    - kube-chainsaw k8s/ --format sarif --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## Next Steps

- [CLI Reference](cli.md): All command-line options
- [CI Integration](../guides/ci-integration.md): GitHub Actions and GitLab CI examples
- [Detection Rules](rules.md): Full rule descriptions for SARIF rule definitions
