# CLI Commands

Complete reference for the `kube-chainsaw` command-line interface.

---

## Basic Usage

```bash
kube-chainsaw scan [PATH] [OPTIONS]
```

**Arguments:**

- `PATH`: Directory, file, or `-` for stdin (default: current directory)

---

## Options

### Input Options

| Option | Description | Default |
|--------|-------------|---------|
| `--exclude-dirs DIRS` | Comma-separated directory names to skip | `""` |
| `--no-default-excludes` | Disable default exclusions (node_modules, vendor, test, .git, examples) | `false` |
| `--stdin` | Read manifests from stdin | `false` |

### Output Options

| Option | Description | Default |
|--------|-------------|---------|
| `--format FORMAT` | Output format: `console`, `json`, `sarif` | `console` |
| `-o, --output FILE` | Write output to file (dual mode: SARIF to file, console to stdout) | `""` |
| `--verbose` | Enable verbose logging (includes suppressed findings) | `false` |
| `--quiet` | Suppress all output except errors | `false` |

### Severity and Filtering

| Option | Description | Default |
|--------|-------------|---------|
| `--fail-on-severity LEVEL` | Exit with code 1 if findings at or above this level: `critical`, `high`, `medium`, `low` | `high` |
| `--min-severity LEVEL` | Only report findings at or above this level | `low` |
| `--suppressions FILE` | Path to suppression file (comma-separated for multiple files) | `.kube-chainsaw-suppressions.yaml` |

### Plugin Options (Paid Addon)

| Option | Description | Default |
|--------|-------------|---------|
| `--plugin-secrets` | Enable secret content analysis | `false` |
| `--plugin-runtime` | Enable runtime cluster correlation | `false` |
| `--custom-rules FILE` | Path to custom rules file | `""` |
| `--license-key KEY` | Plugin license key (or use `KUBE_CHAINSAW_LICENSE_KEY` env var) | `""` |
| `--kubeconfig PATH` | Path to kubeconfig for runtime analysis | `~/.kube/config` |

### Other Options

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help message and exit |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings, or all findings below `--fail-on-severity` threshold |
| `1` | Findings at or above `--fail-on-severity` threshold |
| `2` | Scan error (invalid YAML, file not found, permission denied, etc.) |

---

## Examples

### Scan a directory with default settings:

```bash
kube-chainsaw scan k8s/
```

### Fail only on CRITICAL findings:

```bash
kube-chainsaw scan k8s/ --fail-on-severity critical
```

### Generate SARIF for GitHub Code Scanning:

```bash
kube-chainsaw scan k8s/ --format sarif -o results.sarif
```

This writes SARIF to `results.sarif` and prints a human-readable summary to stdout.

### Scan from stdin:

```bash
cat manifests/*.yaml | kube-chainsaw scan --stdin
```

### Exclude staging directories:

```bash
kube-chainsaw scan k8s/ --exclude-dirs staging,dev
```

### Use custom suppression file:

```bash
kube-chainsaw scan k8s/ --suppressions team-suppressions.yaml
```

### Scan with verbose logging:

```bash
kube-chainsaw scan k8s/ --verbose
```

### Quiet mode (errors only):

```bash
kube-chainsaw scan k8s/ --quiet --format json -o results.json
```

---

## Dual Output Behavior

When using `--format sarif` with `-o FILE`, kube-chainsaw writes SARIF to the file and prints a human-readable summary to stdout:

```bash
kube-chainsaw scan k8s/ --format sarif -o results.sarif
```

**Output:**

- `results.sarif`: SARIF JSON for machine consumption
- `stdout`: Human-readable summary for CI logs

This dual output mode is designed for CI pipelines where you need both machine-readable artifacts and human-readable logs.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KUBE_CHAINSAW_LICENSE_KEY` | Plugin license key (alternative to `--license-key`) |
| `KUBE_CHAINSAW_SUPPRESSIONS` | Default suppression file path (alternative to `--suppressions`) |

---

## Next Steps

- [Detection Rules](rules.md): Full reference of all 15 detection rules
- [Output Formats](output-formats.md): SARIF, JSON, and console output examples
- [Suppressions Guide](../guides/suppressions.md): Suppress false positives or accepted risks
