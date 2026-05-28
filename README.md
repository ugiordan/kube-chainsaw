# kube-chainsaw

Graph-level RBAC privilege chain analysis for Kubernetes manifests.

Builds ServiceAccount -> RoleBinding -> Role -> verb/resource permission graphs from static YAML manifests, catching indirect privilege escalation paths that rule-based tools miss.

## Install

```bash
pip install kube-chainsaw
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

## License

Apache 2.0
