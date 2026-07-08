<p align="center">
  <img src="site/docs/images/logo.svg" alt="kube-chainsaw logo" width="120">
</p>

# kube-chainsaw

Graph-level RBAC privilege chain analysis for Kubernetes manifests.

kube-chainsaw builds permission graphs from static YAML manifests (ServiceAccount -> RoleBinding -> Role -> verb/resource), detecting indirect privilege escalation paths that per-object linters like kube-linter cannot catch. It runs 15 detection rules across three categories: risky permissions, workload-to-cluster-admin chains, and aggregated ClusterRole analysis.

**[Documentation](https://ugiordan.github.io/kube-chainsaw/)** | **[Detection Rules Reference](https://ugiordan.github.io/kube-chainsaw/reference/rules/)** | **[Blog Post](https://developers.redhat.com/articles/2026/07/07/why-your-rbac-linter-misses-privilege-escalation-chains-and-how-fix-it)**

## Install

### Go install (recommended)
```bash
go install github.com/ugiordan/kube-chainsaw/cmd/kube-chainsaw@latest
```

### Binary
Download from [Releases](https://github.com/ugiordan/kube-chainsaw/releases):
```bash
curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/').tar.gz | tar xz
sudo mv kube-chainsaw /usr/local/bin/
```

### GitHub Action
```yaml
- uses: ugiordan/kube-chainsaw@v1
  with:
    paths: config/ deploy/
    fail-on: HIGH
```

## Quick Start

```bash
kube-chainsaw config/ deploy/ --fail-on HIGH
```

Example output:
```
=== HIGH ===

  [KC-006] Secrets access
    File:        config/rbac/role.yaml
    Resource:    ClusterRole/operator-manager-role
    Description: Role "operator-manager-role" grants access to dangerous resource "secrets"
    Remediation: Restrict Secrets access to specific namespaces and only the verbs needed

  [KC-011] Privilege escalation via Role/Binding modification
    File:        config/rbac/role.yaml
    Resource:    ClusterRole/operator-manager-role
    Description: Role "operator-manager-role" can create/modify Roles or Bindings
    Remediation: Restrict ability to create/modify Roles and Bindings to admin users only

Total: 2 findings [2 HIGH]
```

## What It Detects

15 rules across three categories:

- **Risky permissions**: wildcard verbs/resources, dangerous verbs (escalate, impersonate, bind), sensitive resource access (Secrets, pods/exec, nodes), RBAC self-modification
- **Privilege chains**: workloads whose ServiceAccount chains up to cluster-admin, RoleBindings that reference ClusterRoles (scope mismatch)
- **Aggregated ClusterRoles**: label-selector-based role composition where effective permissions can't be fully determined statically

Severity adjusts based on binding scope: cluster-wide bindings are HIGH/CRITICAL, namespace-scoped are WARNING, unbound roles are INFO.

## Why kube-chainsaw?

| Tool | Static Analysis | Graph Traversal | Privilege Chains | Workload Analysis |
|------|:-:|:-:|:-:|:-:|
| **kube-chainsaw** | Yes | Yes | Yes | Yes |
| kube-linter | Yes | No | No | No |
| KubiScan | No (live cluster) | Yes | Yes | No |
| rbac-tool | No (live cluster) | Yes | No | No |
| kubectl-who-can | No (live cluster) | Yes | No | No |

kube-chainsaw is the only tool that performs static graph traversal on YAML manifests to detect privilege escalation chains before deployment, requiring no live cluster.

## Output Formats

- **Console**: human-readable text (default)
- **JSON**: machine-parseable findings
- **SARIF**: integrates with GitHub Code Scanning, GitLab SAST, and any SARIF-compatible platform

```bash
kube-chainsaw config/ --format sarif --output results.sarif
```

## Suppressions

Document accepted risks with a suppressions file:
```yaml
suppressions:
  - rule_id: KC-006
    resource_name: operator-manager-role
    reason: "Operator manages TLS certificates stored as Secrets"
```

```bash
kube-chainsaw config/ --suppressions suppressions.yaml
```

Suppressed findings still appear in output (marked as suppressed) for audit trail but don't affect the exit code.

## API Stability

The following packages are considered stable public API:

- `pkg/analyzer`: `Analyze()`, `KnownRuleIDs()`
- `pkg/models`: `Finding`, `Severity`, `LoadedResources`, and all data types

Breaking changes to these packages follow semver. Internal packages (`pkg/loader`, `pkg/reporter`, `pkg/suppression`) may change without notice.

## License

Apache 2.0
