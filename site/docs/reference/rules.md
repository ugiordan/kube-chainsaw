# Detection Rules

kube-chainsaw implements 31 static analysis rules to detect RBAC misconfigurations, privilege escalation paths, broad NetworkPolicy peers, dangerous workload settings, external exposure, credential manifests, and OpenShift SCC risks.

## Rule Groups

Browse rules by security area:

| Group | Rules |
|---|---|
| [RBAC and Privileges](rules/rbac.md) | KC-001 to KC-015 |
| [Network and Exposure](rules/network.md) | KC-016 to KC-018, KC-025 to KC-027 |
| [Workloads and OpenShift](rules/workload.md) | KC-019 to KC-024 |
| [Secrets and Certificates](rules/secrets.md) | KC-028 to KC-031 |

## Full Rule Index

### RBAC and Privileges

| Rule | Description |
|---|---|
| [KC-001](rules/rbac.md#kc-001-wildcard-resource-access) | Wildcard resource or API group access in Role/ClusterRole |
| [KC-002](rules/rbac.md#kc-002-wildcard-verb-access) | Wildcard verb access in Role/ClusterRole |
| [KC-003](rules/rbac.md#kc-003-escalate-verb-permission) | `escalate` verb permission |
| [KC-004](rules/rbac.md#kc-004-impersonate-verb-permission) | `impersonate` verb permission |
| [KC-005](rules/rbac.md#kc-005-bind-verb-permission) | `bind` verb permission |
| [KC-006](rules/rbac.md#kc-006-secrets-access) | Access to core `secrets` resources |
| [KC-007](rules/rbac.md#kc-007-dangerous-pod-subresource-access) | Access to `pods/exec`, `pods/attach`, `pods/log`, `pods/ephemeralcontainers` |
| [KC-008](rules/rbac.md#kc-008-node-level-access) | Access to `nodes` or `nodes/proxy` |
| [KC-009](rules/rbac.md#kc-009-persistentvolume-access) | Access to `persistentvolumes` |
| [KC-010](rules/rbac.md#kc-010-rbac-modification-capability) | Access to `clusterroles` or `clusterrolebindings` |
| [KC-011](rules/rbac.md#kc-011-privilege-escalation-via-rolebinding-modification) | Mutation verbs on RBAC resources |
| [KC-012](rules/rbac.md#kc-012-privilege-escalation-via-workload-creation) | Create permission on workload resources |
| [KC-013](rules/rbac.md#kc-013-pod-running-with-cluster-admin-privileges) | Pod ServiceAccount bound to `cluster-admin` |
| [KC-014](rules/rbac.md#kc-014-rolebinding-referencing-clusterrole) | RoleBinding referencing a ClusterRole |
| [KC-015](rules/rbac.md#kc-015-aggregated-clusterrole-detected) | ClusterRole using `aggregationRule` |

### Network and Exposure

| Rule | Description |
|---|---|
| [KC-016](rules/network.md#kc-016-networkpolicy-access) | RBAC access to `networkpolicies` |
| [KC-017](rules/network.md#kc-017-networkpolicy-allows-ingress-from-broad-peers) | Ingress rules with broad or missing peers |
| [KC-018](rules/network.md#kc-018-networkpolicy-allows-egress-to-broad-destinations) | Egress rules with broad or missing destinations |
| [KC-025](rules/network.md#kc-025-external-service-exposure) | `LoadBalancer`, `NodePort`, `ExternalName`, or `externalIPs` |
| [KC-026](rules/network.md#kc-026-unencrypted-external-route) | Ingress or Route without TLS |
| [KC-027](rules/network.md#kc-027-broad-external-route) | Catch-all, wildcard, or subdomain routing |

### Workloads and OpenShift

| Rule | Description |
|---|---|
| [KC-019](rules/workload.md#kc-019-privileged-container-requested) | `securityContext.privileged: true` |
| [KC-020](rules/workload.md#kc-020-host-namespace-access-requested) | `hostNetwork`, `hostPID`, or `hostIPC` |
| [KC-021](rules/workload.md#kc-021-hostpath-volume-requested) | `hostPath` volumes |
| [KC-022](rules/workload.md#kc-022-dangerous-linux-capability-requested) | Dangerous added Linux capabilities |
| [KC-023](rules/workload.md#kc-023-openshift-securitycontextconstraints-use-permission) | RBAC `use` permission on SCCs |
| [KC-024](rules/workload.md#kc-024-permissive-openshift-securitycontextconstraints-assignment) | Permissive SCC assigned to broad subjects |

### Secrets and Certificates

| Rule | Description |
|---|---|
| [KC-028](rules/secrets.md#kc-028-credential-material-in-secret-manifest) | Credential-bearing Secret manifests |
| [KC-029](rules/secrets.md#kc-029-long-lived-serviceaccount-token-secret) | Long-lived ServiceAccount token Secrets |
| [KC-030](rules/secrets.md#kc-030-serviceaccount-token-minting-permission) | RBAC access to `serviceaccounts/token` |
| [KC-031](rules/secrets.md#kc-031-certificatesigningrequest-approval-or-signing-permission) | CSR approval or signing permission |

---

## Rule Severity Model

Finding severity is dynamic, based on how the role is bound:

| Condition | Severity |
|-----------|----------|
| Cluster-wide binding with wildcards | CRITICAL |
| Cluster-wide binding without wildcards | HIGH |
| Namespace-scoped binding with wildcards | HIGH |
| Namespace-scoped binding without wildcards | WARNING |
| Unbound role (no binding found) | INFO |

Namespace-scoped Roles are capped at WARNING regardless of binding scope.

Special cases:
- KC-013 (cluster-admin pod) is always CRITICAL
- KC-014 (RoleBinding to ClusterRole) is always WARNING
- KC-015 (aggregated ClusterRole) is always INFO
- KC-017 and KC-018 are HIGH when the policy selects all pods in its namespace, otherwise WARNING
- KC-019 and KC-020 are always HIGH
- KC-021 and KC-022 are HIGH only for sensitive paths or high-risk capabilities, otherwise WARNING
- KC-024 is HIGH for broad SCC subjects, otherwise WARNING
- KC-025 and KC-027 are WARNING
- KC-026 is HIGH for `insecureEdgeTerminationPolicy: Allow`, otherwise WARNING
- KC-028 is WARNING and KC-029 is HIGH

---

## Next Steps

- [Understanding Findings](../guides/findings.md): Learn how to interpret and act on findings
- [Suppressions](../guides/suppressions.md): Suppress accepted risks or false positives
- [CLI Reference](cli.md): Control severity thresholds and output formats
