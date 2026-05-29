# CI Integration

kube-chainsaw integrates with GitHub Actions, GitLab CI, and other CI platforms through exit codes, SARIF output, and suppression files.

---

## GitHub Actions

### Using the GitHub Action (Recommended)

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
      
      - name: Run kube-chainsaw
        uses: ugiordan/kube-chainsaw@v1
        with:
          paths: k8s/ deploy/
          fail-on: HIGH
          format: sarif
          output: kube-chainsaw.sarif
      
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: kube-chainsaw.sarif
        if: always()
```

### Manual Installation

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
      
      - name: Install kube-chainsaw
        run: |
          curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_linux_amd64.tar.gz | tar xz
          sudo mv kube-chainsaw /usr/local/bin/
      
      - name: Scan manifests
        run: kube-chainsaw k8s/ --format sarif --output kube-chainsaw.sarif
      
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
  run: kube-chainsaw k8s/ --fail-on CRITICAL
```

Or using the action:

```yaml
- name: Run kube-chainsaw
  uses: ugiordan/kube-chainsaw@v1
  with:
    paths: k8s/
    fail-on: CRITICAL
```

---

## GitLab CI

### Basic Pipeline

```yaml
rbac-scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl tar
    - curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_linux_amd64.tar.gz | tar xz
    - mv kube-chainsaw /usr/local/bin/
  script:
    - kube-chainsaw k8s/ --format sarif --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
```

### With Suppressions

```yaml
rbac-scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl tar
    - curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_linux_amd64.tar.gz | tar xz
    - mv kube-chainsaw /usr/local/bin/
  script:
    - kube-chainsaw k8s/ --suppressions suppressions.yaml
  allow_failure:
    exit_codes: 1  # Allow findings below CRITICAL
```

---

## Jenkins

### Declarative Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Install kube-chainsaw') {
            steps {
                sh '''
                    curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_linux_amd64.tar.gz | tar xz
                    sudo mv kube-chainsaw /usr/local/bin/
                '''
            }
        }
        
        stage('RBAC Security Scan') {
            steps {
                sh 'kube-chainsaw k8s/ --format json --output results.json'
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

Create a local hook in `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: kube-chainsaw
        name: kube-chainsaw RBAC scan
        entry: kube-chainsaw
        language: system
        args: ['--fail-on', 'HIGH']
        files: '^k8s/.*\.ya?ml$'
        pass_filenames: false
```

Run locally:

```bash
pre-commit install
pre-commit run --all-files
```

This assumes `kube-chainsaw` is installed and available in your PATH.

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
kube-chainsaw k8s/ --fail-on CRITICAL
echo $?  # 0 if no CRITICAL findings, 1 if CRITICAL found, 2 on error
```

---

## Dual Output Mode

kube-chainsaw can write output to a file while also printing a summary to stdout. Specify `--output` to write to a file and `--format` for stdout:

```bash
kube-chainsaw k8s/ --format console --output results.json
```

Or write SARIF to file while printing console output:

```bash
kube-chainsaw k8s/ --format sarif --output results.sarif
```

When `--output` is specified without `--output-format`, the format is inferred from the file extension (`.sarif` or `.json`).

Perfect for CI pipelines where you need both machine-readable artifacts and human-readable logs.

---

## Suppression Files in CI

Commit `suppressions.yaml` to version control:

```yaml
suppressions:
- rule_id: KC-001
  resource_name: admin-cluster-role
  reason: "Required for cluster operator"
```

Reference it in CI:

```bash
kube-chainsaw k8s/ --suppressions suppressions.yaml
```

See [Suppressions Guide](suppressions.md) for full syntax.

---

## Next Steps

- [Understanding Findings](findings.md): Interpret severity levels and recommendations
- [Suppressions](suppressions.md): Suppress false positives or accepted risks
- [Output Formats](../reference/output-formats.md): SARIF, JSON, and console output details
