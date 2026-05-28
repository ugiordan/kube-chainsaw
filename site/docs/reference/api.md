# Python API

kube-chainsaw can be used as a Python library for custom integrations and tooling.

---

## Installation

```bash
pip install kube-chainsaw
```

---

## Basic Usage

```python
from kube_chainsaw import Scanner, SeverityLevel

# Create a scanner instance
scanner = Scanner()

# Scan a directory
findings = scanner.scan_directory("k8s/manifests/")

# Filter by severity
critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]

# Print findings
for finding in findings:
    print(f"{finding.severity.name}: {finding.message}")
    print(f"  Location: {finding.location.file}:{finding.location.line}")
```

---

## Scanner API

### `Scanner()`

Create a scanner instance.

**Parameters:**

- `exclude_dirs` (list[str], optional): Directory names to exclude
- `use_default_excludes` (bool, default=True): Whether to use default exclusions
- `min_severity` (SeverityLevel, optional): Minimum severity to report
- `suppressions_file` (str, optional): Path to suppression file

**Example:**

```python
scanner = Scanner(
    exclude_dirs=["staging", "dev"],
    min_severity=SeverityLevel.HIGH,
    suppressions_file=".kube-chainsaw-suppressions.yaml"
)
```

---

### `scan_directory(path: str) -> list[Finding]`

Scan a directory of Kubernetes manifests.

**Example:**

```python
findings = scanner.scan_directory("k8s/")
```

---

### `scan_file(path: str) -> list[Finding]`

Scan a single YAML file.

**Example:**

```python
findings = scanner.scan_file("k8s/roles.yaml")
```

---

### `scan_yaml(content: str, filename: str = "<stdin>") -> list[Finding]`

Scan YAML content from a string.

**Example:**

```python
yaml_content = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
"""

findings = scanner.scan_yaml(yaml_content, filename="test.yaml")
```

---

## Finding Object

Each finding has the following attributes:

```python
class Finding:
    rule_id: str              # e.g., "KC-001"
    severity: SeverityLevel   # CRITICAL, HIGH, MEDIUM, LOW
    message: str              # Human-readable description
    impact: str               # Security impact
    recommendation: str       # How to fix
    location: Location        # File, line, column
    resource: Resource        # Kind, name, namespace
    metadata: dict            # Rule-specific metadata
```

**Example:**

```python
for finding in findings:
    print(f"[{finding.severity.name}] {finding.rule_id}: {finding.message}")
    print(f"  File: {finding.location.file}:{finding.location.line}")
    print(f"  Resource: {finding.resource.kind}/{finding.resource.name}")
    print(f"  Impact: {finding.impact}")
    print(f"  Fix: {finding.recommendation}")
    print()
```

---

## Severity Levels

```python
from kube_chainsaw import SeverityLevel

# Enum values
SeverityLevel.CRITICAL  # 4
SeverityLevel.HIGH      # 3
SeverityLevel.MEDIUM    # 2
SeverityLevel.LOW       # 1

# Comparison
finding.severity >= SeverityLevel.HIGH
```

---

## Output Formats

### Console Output

```python
from kube_chainsaw import ConsoleReporter

reporter = ConsoleReporter()
reporter.print_findings(findings)
```

### JSON Output

```python
from kube_chainsaw import JSONReporter

reporter = JSONReporter()
json_output = reporter.generate_report(findings)

# Write to file
with open("results.json", "w") as f:
    f.write(json_output)
```

### SARIF Output

```python
from kube_chainsaw import SARIFReporter

reporter = SARIFReporter()
sarif_output = reporter.generate_report(findings)

# Write to file
with open("results.sarif", "w") as f:
    f.write(sarif_output)
```

---

## Custom Rules

Define custom detection rules:

```python
from kube_chainsaw import Rule, RuleContext

class CustomRule(Rule):
    rule_id = "CUSTOM-001"
    severity = SeverityLevel.HIGH
    
    def check(self, context: RuleContext) -> list[Finding]:
        findings = []
        
        for resource in context.roles:
            if resource.metadata.name.startswith("admin-"):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message=f"Role name '{resource.metadata.name}' violates naming policy",
                    location=resource.location,
                    resource=resource
                ))
        
        return findings

# Register custom rule
scanner = Scanner()
scanner.add_rule(CustomRule())

findings = scanner.scan_directory("k8s/")
```

---

## Graph API

Access the RBAC permission graph:

```python
from kube_chainsaw import GraphBuilder

builder = GraphBuilder()
graph = builder.build_from_directory("k8s/")

# Query the graph
role = graph.get_role("pod-reader")
bindings = graph.get_bindings_for_role(role)
service_accounts = graph.get_service_accounts_for_role(role)

# Traverse privilege escalation paths
paths = graph.find_escalation_paths(
    from_service_account="viewer-sa",
    to_permission="cluster-admin"
)

for path in paths:
    print(f"Escalation path: {' -> '.join(path.steps)}")
```

---

## Complete Example

```python
from kube_chainsaw import Scanner, SeverityLevel, ConsoleReporter, SARIFReporter

# Create scanner with custom config
scanner = Scanner(
    exclude_dirs=["test", "examples"],
    min_severity=SeverityLevel.HIGH,
    suppressions_file=".kube-chainsaw-suppressions.yaml"
)

# Scan directory
findings = scanner.scan_directory("k8s/manifests/")

# Print console report
console_reporter = ConsoleReporter()
console_reporter.print_findings(findings)

# Save SARIF for CI
sarif_reporter = SARIFReporter()
sarif_output = sarif_reporter.generate_report(findings)

with open("results.sarif", "w") as f:
    f.write(sarif_output)

# Exit with code 1 if any HIGH or CRITICAL findings
critical_or_high = [f for f in findings if f.severity >= SeverityLevel.HIGH]
exit(1 if critical_or_high else 0)
```

---

## Next Steps

- [CLI Reference](cli.md): Command-line usage
- [Detection Rules](rules.md): Built-in rules
- [Contributing](../contributing/rules.md): Add custom rules to the project
