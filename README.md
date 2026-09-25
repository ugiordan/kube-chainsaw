<p align="center">
  <img src="site/docs/images/logo.svg" alt="kube-chainsaw logo" width="120">
</p>

# kube-chainsaw

Graph-level RBAC and NetworkPolicy security analysis for Kubernetes manifests.

kube-chainsaw builds permission graphs from YAML manifests or live clusters (ServiceAccount -> RoleBinding -> Role -> verb/resource), and analyzes NetworkPolicy peer scope. It detects indirect privilege escalation paths and broad network access patterns that per-object linters like kube-linter cannot catch. It runs 18 detection rules across RBAC, privilege-chain, aggregation, and NetworkPolicy categories.

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

### Container (Docker / Podman)
```bash
docker run --rm -v $(pwd):/scan ghcr.io/ugiordan/kube-chainsaw:latest /scan/config
```
```bash
podman run --rm -v $(pwd):/scan ghcr.io/ugiordan/kube-chainsaw:latest /scan/config
```

### GitHub Action
```yaml
- uses: ugiordan/kube-chainsaw@v1
  with:
    paths: config/ deploy/
    fail-on: HIGH
```

## Quick Start

Scan local manifests:
```bash
kube-chainsaw config/ deploy/ --fail-on HIGH
```

Runnable NetworkPolicy examples are in [`examples/networkpolicy/`](examples/networkpolicy/).

Scan a live cluster:
```bash
kube-chainsaw --from-cluster --fail-on HIGH
```

Scan a specific namespace:
```bash
kube-chainsaw --from-cluster --namespace my-app --fail-on HIGH
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

18 rules across four categories:

- **Risky permissions**: wildcard verbs/resources, dangerous verbs (escalate, impersonate, bind), sensitive resource access (Secrets, pods/exec, nodes), RBAC self-modification, and NetworkPolicy access
- **Privilege chains**: workloads whose ServiceAccount chains up to cluster-admin, RoleBindings that reference ClusterRoles (scope mismatch)
- **Aggregated ClusterRoles**: label-selector-based role composition where effective permissions can't be fully determined statically
- **NetworkPolicy**: policies that allow ingress from broad peers or egress to broad destinations

Severity adjusts based on binding scope: cluster-wide bindings are HIGH/CRITICAL, namespace-scoped are WARNING, unbound roles are INFO.
NetworkPolicy findings are HIGH when they select every pod in a namespace and WARNING for narrower pod selectors.

## Why kube-chainsaw?

| Tool | Static Analysis | Live Cluster | Graph Traversal | Privilege Chains | Workload Analysis |
|------|:-:|:-:|:-:|:-:|:-:|
| **kube-chainsaw** | Yes | Yes | Yes | Yes | Yes |
| kube-linter | Yes | No | No | No | No |
| KubiScan | No | Yes | Yes | Yes | No |
| rbac-tool | No | Yes | Yes | No | No |
| kubectl-who-can | No | Yes | Yes | No | No |

kube-chainsaw performs graph traversal and policy analysis on YAML manifests. It works on static files (pre-deployment) or live clusters via `--from-cluster` (using kubectl).

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
