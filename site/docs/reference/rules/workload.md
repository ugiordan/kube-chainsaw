# Workload and OpenShift Rules

These rules inspect declared workload security contexts and OpenShift SecurityContextConstraints assignments.

| Rules | Focus |
|---|---|
| [KC-019](../rules.md#kc-019-privileged-container-requested) | Privileged containers |
| [KC-020](../rules.md#kc-020-host-namespace-access-requested) | Host network, PID, and IPC namespaces |
| [KC-021](../rules.md#kc-021-hostpath-volume-requested) | Mounted hostPath volumes |
| [KC-022](../rules.md#kc-022-dangerous-linux-capability-requested) | Dangerous Linux capabilities |
| [KC-023](../rules.md#kc-023-openshift-securitycontextconstraints-use-permission) | RBAC SCC `use` permissions |
| [KC-024](../rules.md#kc-024-permissive-openshift-securitycontextconstraints-assignment) | Directly assigned permissive SCCs |

Built-in permissive SCCs without direct subjects are not reported by KC-024. Review their RBAC `use` permissions with KC-023 instead.

See the runnable examples in [`examples/security/`](https://github.com/ugiordan/kube-chainsaw/tree/main/examples/security).
