# Output Formats

kube-chainsaw supports three output formats: console, JSON, and SARIF.

---

## Console (Default)

Human-readable output with color-coded severity levels and actionable recommendations.

**Usage:**

```bash
kube-chainsaw scan k8s/
```

**Example output:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 kube-chainsaw scan results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] KC-007: Privilege escalation chain detected
  Path: viewer-sa -> viewer-role -> pods/exec -> admin-sa-token
  Steps: 3
  Impact: ServiceAccount 'viewer-sa' can escalate to cluster-admin
  Recommendation: Remove pods/exec permission from viewer-role

[HIGH] KC-001: Wildcard verbs in ClusterRole 'pod-manager'
  Location: k8s/roles.yaml:15:11
  Impact: Grants create, delete, patch, and escalate permissions
  Recommendation: Replace '*' with explicit verbs: ['get', 'list', 'watch']
  ServiceAccounts bound: admin-sa (via admin-binding)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 2 findings (1 critical, 1 high, 0 medium, 0 low)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Exit code: 1 (findings with severity >= high)
```

---

## JSON

Machine-readable JSON output for custom integrations.

**Usage:**

```bash
kube-chainsaw scan k8s/ --format json -o results.json
```

**Example output:**

```json
{
  "version": "1.0",
  "findings": [
    {
      "rule_id": "KC-001",
      "severity": "high",
      "message": "Wildcard verbs in ClusterRole 'pod-manager'",
      "location": {
        "file": "k8s/roles.yaml",
        "line": 15,
        "column": 11
      },
      "resource": {
        "kind": "ClusterRole",
        "name": "pod-manager",
        "namespace": null
      },
      "impact": "Grants create, delete, patch, and escalate permissions",
      "recommendation": "Replace '*' with explicit verbs: ['get', 'list', 'watch']",
      "metadata": {
        "bound_service_accounts": ["admin-sa"],
        "bindings": ["admin-binding"]
      }
    }
  ],
  "summary": {
    "total": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

---

## SARIF

Static Analysis Results Interchange Format (SARIF) for GitHub Code Scanning, GitLab SAST, and other security platforms.

**Usage:**

```bash
kube-chainsaw scan k8s/ --format sarif -o results.sarif
```

**Example output:**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
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
              "name": "WildcardVerbs",
              "shortDescription": {
                "text": "Wildcard verbs in Role or ClusterRole"
              },
              "fullDescription": {
                "text": "Detects verbs: ['*'] in RBAC rules, which grants excessive permissions"
              },
              "help": {
                "text": "Replace '*' with explicit verbs like ['get', 'list', 'watch']"
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "precision": "high",
                "security-severity": "8.0"
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
            "text": "Wildcard verbs in ClusterRole 'pod-manager'"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "k8s/roles.yaml"
                },
                "region": {
                  "startLine": 15,
                  "startColumn": 11
                }
              }
            }
          ],
          "fingerprints": {
            "kube-chainsaw/v1": "KC-001:ClusterRole:pod-manager:k8s/roles.yaml:15:11"
          }
        }
      ]
    }
  ]
}
```

**SARIF Features:**

- **Fingerprints**: Stable identifiers for deduplication across scans
- **Security-severity**: Numeric score for severity ranking (0.0-10.0)
- **Help URLs**: Links to documentation for each rule
- **Code flows**: Multi-step privilege escalation paths (for KC-007, KC-008)

---

## Dual Output Mode

When using `--format sarif` with `-o FILE`, kube-chainsaw writes SARIF to the file and prints a console summary to stdout:

```bash
kube-chainsaw scan k8s/ --format sarif -o results.sarif
```

**Behavior:**

- `results.sarif`: SARIF JSON for machine consumption
- `stdout`: Human-readable summary for CI logs

This is the recommended mode for CI pipelines.

---

## GitHub Code Scanning Integration

Upload SARIF to GitHub Code Scanning:

```yaml
- name: Run kube-chainsaw
  run: kube-chainsaw scan k8s/ --format sarif -o kube-chainsaw.sarif

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
    - kube-chainsaw scan k8s/ --format sarif -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## Next Steps

- [CLI Reference](cli.md): All command-line options
- [CI Integration](../guides/ci-integration.md): GitHub Actions and GitLab CI examples
- [Detection Rules](rules.md): Full rule descriptions for SARIF rule definitions
