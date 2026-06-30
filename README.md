# kube-chainsaw

Graph-level RBAC privilege chain analysis for Kubernetes manifests.

Builds ServiceAccount -> RoleBinding -> Role -> verb/resource permission graphs from static YAML manifests, catching indirect privilege escalation paths that rule-based tools miss.

## Install

### Binary (recommended)
Download from [Releases](https://github.com/ugiordan/kube-chainsaw/releases):
```bash
curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_linux_amd64.tar.gz | tar xz
sudo mv kube-chainsaw /usr/local/bin/
```

### Go install
```bash
go install github.com/ugiordan/kube-chainsaw/cmd/kube-chainsaw@latest
```

### Docker
```bash
docker run --rm -v $(pwd):/scan ghcr.io/ugiordan/kube-chainsaw:latest /scan/config
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

## Why kube-chainsaw?

No existing tool does graph-level RBAC analysis on static manifests:

| Tool | Static Analysis | Graph Traversal | Privilege Chains |
|------|:-:|:-:|:-:|
| **kube-chainsaw** | Yes | Yes | Yes |
| kube-linter | Yes | No | No |
| KubiScan | No (live cluster) | Partial | No |
| rbac-tool | No (live cluster) | Yes | No |
| kubectl-who-can | No (live cluster) | No | No |

## API Stability

The following packages are considered stable public API:

- `pkg/analyzer` - `Analyze()`, `KnownRuleIDs()`
- `pkg/models` - `Finding`, `Severity`, `LoadedResources`, and all data types

Breaking changes to these packages will follow semver. The `pkg/loader`, `pkg/reporter`, and `pkg/suppression` packages are internal and may change without notice.

## License

Apache 2.0
