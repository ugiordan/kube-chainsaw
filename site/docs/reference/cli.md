# CLI Commands

Complete reference for the `kube-chainsaw` command-line interface.

---

## Basic Usage

```bash
kube-chainsaw [paths...] [OPTIONS]
```

**Arguments:**

- `paths`: One or more directories or files to scan (required)

---

## Options

### Input Options

| Option | Description | Default |
|--------|-------------|---------|
| `--exclude-dirs DIRS` | Comma-separated directory names to skip | `""` |
| `--no-default-excludes` | Disable default exclusions (.git, vendor, node_modules, bin) | `false` |

### Output Options

| Option | Description | Default |
|--------|-------------|---------|
| `--format FORMAT` | Output format for stdout: `console`, `json`, `sarif` | `console` |
| `--output FILE` | Write report to file | `""` |
| `--output-format FORMAT` | Format for --output file: `json`, `sarif` (inferred from extension if omitted) | `""` |
| `--quiet` | Suppress stdout output | `false` |

### Severity and Filtering

| Option | Description | Default |
|--------|-------------|---------|
| `--fail-on LEVEL` | Exit with code 1 if findings at or above this level: `CRITICAL`, `HIGH`, `WARNING`, `INFO` | `CRITICAL` |
| `--suppressions FILE` | Path to suppression YAML file | `""` |

### Other Options

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help message and exit |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `--fail-on` threshold, or all findings suppressed |
| `1` | Findings at or above `--fail-on` threshold |
| `2` | Runtime error (invalid arguments, file not found, permission denied, etc.) |

---

## Examples

### Scan a directory with default settings:

```bash
kube-chainsaw k8s/
```

### Scan multiple directories:

```bash
kube-chainsaw config/ deploy/ manifests/
```

### Fail only on CRITICAL findings:

```bash
kube-chainsaw k8s/ --fail-on CRITICAL
```

### Fail on HIGH or CRITICAL:

```bash
kube-chainsaw k8s/ --fail-on HIGH
```

### Generate JSON output to file:

```bash
kube-chainsaw k8s/ --format json --output results.json
```

### Generate SARIF for GitHub Code Scanning:

```bash
kube-chainsaw k8s/ --format sarif --output results.sarif
```

This writes SARIF to `results.sarif` and prints a human-readable summary to stdout.

### Exclude staging directories:

```bash
kube-chainsaw k8s/ --exclude-dirs staging,dev
```

### Use custom suppression file:

```bash
kube-chainsaw k8s/ --suppressions team-suppressions.yaml
```

### Quiet mode (no stdout, write to file only):

```bash
kube-chainsaw k8s/ --quiet --output results.json
```

---

## Dual Output Behavior

When using `--output`, kube-chainsaw can write to a file while also printing to stdout:

```bash
kube-chainsaw k8s/ --output results.json
```

**Behavior:**

- `results.json`: JSON output
- `stdout`: Console format (unless `--quiet`)

When `--format` is specified, it controls the stdout format. When `--output-format` is specified, it controls the file format. If `--output-format` is omitted, the format is inferred from the file extension (`.sarif` for SARIF, otherwise JSON).

This dual output mode is designed for CI pipelines where you need both machine-readable artifacts and human-readable logs.

---

## File Size and Document Limits

kube-chainsaw enforces limits to prevent resource exhaustion:

- **Max file size**: 10 MB per YAML file
- **Max documents per file**: 10,000 YAML documents per file
- **Suppression file size**: 1 MB max

Files exceeding these limits are logged to stderr and skipped.

---

## Default Directory Exclusions

By default, these directories are skipped:

- `.git/`
- `vendor/`
- `node_modules/`
- `bin/`

Use `--no-default-excludes` to disable this behavior.

---

## Next Steps

- [Detection Rules](rules.md): Full reference of all 15 detection rules
- [Output Formats](output-formats.md): SARIF, JSON, and console output examples
- [Suppressions Guide](../guides/suppressions.md): Suppress false positives or accepted risks
