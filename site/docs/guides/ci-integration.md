# CI Integration

kube-chainsaw integrates with GitHub Actions, GitLab CI, and other CI platforms through exit codes, SARIF output, and suppression files.

---

## GitHub Actions

### Basic Workflow

```yaml
name: RBAC Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  rbac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install kube-chainsaw
        run: pip install kube-chainsaw
      
      - name: Scan manifests
        run: kube-chainsaw scan k8s/ --format sarif -o kube-chainsaw.sarif
      
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: kube-chainsaw.sarif
        if: always()
```

### With Custom Severity Threshold

Fail the build only on CRITICAL findings:

```yaml
- name: Scan manifests
  run: kube-chainsaw scan k8s/ --fail-on-severity critical
```

### Using the GitHub Action

```yaml
- name: Run kube-chainsaw
  uses: ugiordan/kube-chainsaw-action@v1
  with:
    directory: k8s/
    fail-on-severity: high
    exclude-dirs: 'vendor,test'
```

---

## GitLab CI

### Basic Pipeline

```yaml
rbac-scan:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install kube-chainsaw
  script:
    - kube-chainsaw scan k8s/ --format sarif -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
```

### With Suppressions

```yaml
rbac-scan:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install kube-chainsaw
  script:
    - kube-chainsaw scan k8s/ --suppressions .kube-chainsaw-suppressions.yaml
  allow_failure:
    exit_codes: 1  # Allow HIGH findings, fail on CRITICAL
```

---

## Jenkins

### Declarative Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('RBAC Security Scan') {
            steps {
                sh 'pip install kube-chainsaw'
                sh 'kube-chainsaw scan k8s/ --format json -o results.json'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'results.json', allowEmptyArchive: true
        }
    }
}
```

---

## Pre-Commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ugiordan/kube-chainsaw
    rev: v1.0.0
    hooks:
      - id: kube-chainsaw
        args: ['--fail-on-severity', 'high']
        files: '^k8s/.*\.ya?ml$'
```

Run locally:

```bash
pre-commit install
pre-commit run --all-files
```

---

## Exit Code Behavior

kube-chainsaw uses exit codes for CI gates:

| Exit Code | Meaning |
|-----------|---------|
| `0` | No findings, or all findings below `--fail-on-severity` threshold |
| `1` | Findings at or above `--fail-on-severity` threshold |
| `2` | Scan error (invalid YAML, file not found, etc.) |

**Example:** Fail only on CRITICAL findings:

```bash
kube-chainsaw scan k8s/ --fail-on-severity critical
echo $?  # 0 if no CRITICAL findings, 1 if CRITICAL found, 2 on error
```

---

## Dual Output Mode

kube-chainsaw can write SARIF to a file while also printing human-readable output to the console:

```bash
kube-chainsaw scan k8s/ --format sarif -o results.sarif
```

This command:

1. Writes SARIF to `results.sarif`
2. Prints human-readable summary to stdout
3. Returns exit code based on `--fail-on-severity`

Perfect for CI pipelines where you need both machine-readable artifacts and human-readable logs.

---

## Suppression Files in CI

Commit `.kube-chainsaw-suppressions.yaml` to version control:

```yaml
- rule_id: KC-001
  resource_name: admin-cluster-role
  justification: "Required for cluster operator"
  expiry: "2027-06-01"
```

Reference it in CI:

```bash
kube-chainsaw scan k8s/ --suppressions .kube-chainsaw-suppressions.yaml
```

See [Suppressions Guide](suppressions.md) for full syntax.

---

## Next Steps

- [Understanding Findings](findings.md): Interpret severity levels and recommendations
- [Suppressions](suppressions.md): Suppress false positives or accepted risks
- [Output Formats](../reference/output-formats.md): SARIF, JSON, and console output details
