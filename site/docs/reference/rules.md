# Detection Rules

kube-chainsaw implements 15 static analysis rules to detect RBAC misconfigurations and privilege escalation paths.

---

## KC-001: Wildcard Resource Access

**Severity:** Varies (CRITICAL when cluster-wide with wildcards, HIGH when cluster-wide, WARNING when namespace-scoped, INFO when unbound)

**Description:** Detects `resources: ["*"]` in Role or ClusterRole rules, or `apiGroups: ["*"]` which grants access to all API groups including CRDs. Wildcard resources match all resource types in the specified API group.

**Impact:** Grants access to all resource types in the API group, including secrets, configmaps, service accounts, and any future resources added to the group.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["*"]  # Triggers KC-001
  verbs: ["get"]
```

**Recommendation:** Replace `*` with explicit resource names:

```yaml
resources: ["pods", "services", "endpoints"]
```

---

## KC-002: Wildcard Verb Access

**Severity:** Varies (CRITICAL when cluster-wide with wildcards, HIGH when cluster-wide, WARNING when namespace-scoped, INFO when unbound)

**Description:** Detects `verbs: ["*"]` in Role or ClusterRole rules. Wildcard verbs grant all actions including create, delete, patch, update, and escalate.

**Impact:** Grants create, delete, patch, update, and escalate permissions, allowing unintended privilege escalation.

**Example:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-manager
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["*"]  # Triggers KC-002
```

**Recommendation:** Replace `*` with explicit verbs:

```yaml
verbs: ["get", "list", "watch"]
```

---

## KC-003: Escalate Verb Permission

**Severity:** Varies by binding scope

**Description:** Detects the `escalate` verb in Role or ClusterRole rules. The `escalate` verb allows a user to grant permissions they don't already have, bypassing RBAC restrictions.

**Impact:** A principal with the escalate verb can modify roles to grant themselves or others any permission, effectively bypassing all RBAC controls.

**Example:**

```yaml
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["escalate"]  # Triggers KC-003
```

**Recommendation:** Remove the `escalate` verb unless absolutely required for RBAC management tooling.

---

## KC-004: Impersonate Verb Permission

**Severity:** Varies by binding scope

**Description:** Detects the `impersonate` verb in Role or ClusterRole rules. The impersonate verb allows acting as another user, group, or service account.

**Impact:** A principal with the impersonate verb can assume the identity of any other principal, inheriting all their permissions.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]  # Triggers KC-004
```

**Recommendation:** Remove the `impersonate` verb unless required for proxy or delegation use cases.

---

## KC-005: Bind Verb Permission

**Severity:** Varies by binding scope

**Description:** Detects the `bind` verb in Role or ClusterRole rules. The bind verb allows creating bindings to roles with higher privileges than the caller currently has.

**Impact:** A principal with the bind verb can bind themselves or others to any role, including roles with elevated privileges they don't currently possess.

**Example:**

```yaml
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["bind"]  # Triggers KC-005
```

**Recommendation:** Remove the `bind` verb unless required for RBAC management tooling.

---

## KC-006: Secrets Access

**Severity:** Varies by binding scope

**Description:** Detects roles with any access to `secrets` resources in the core API group (`apiGroups: [""]`). Only triggers when the apiGroup is the core group or wildcard, not for CRDs that happen to be named "secrets" in custom API groups.

**Impact:** Allows reading, creating, or modifying credentials, tokens, TLS certificates, and other sensitive data stored as Kubernetes secrets.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]  # Triggers KC-006
  verbs: ["get", "list"]
```

**Recommendation:** Restrict secrets access to specific namespaces and only the verbs needed. Consider using external secrets management.

---

## KC-007: Pod Exec/Attach Access

**Severity:** Varies by binding scope

**Description:** Detects roles with access to `pods/exec` or `pods/attach` subresources in the core API group. Only triggers when the apiGroup is the core group or wildcard.

**Impact:** Allows execution of arbitrary commands inside running containers or attaching to container processes, which can lead to container escape or credential theft.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["pods/exec"]  # Triggers KC-007
  verbs: ["create"]
```

**Recommendation:** Restrict exec/attach to specific namespaces and add audit logging. Grant only to operators and CI/CD systems that require it.

---

## KC-008: Node-Level Access

**Severity:** Varies by binding scope

**Description:** Detects roles with access to `nodes` resources in the core API group. Only triggers when the apiGroup is the core group or wildcard.

**Impact:** Grants access to node-level operations. Write access to nodes can allow modification of node labels, taints, and conditions, potentially disrupting scheduling or enabling privilege escalation via node-level attacks.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["nodes"]  # Triggers KC-008
  verbs: ["get", "list", "watch", "update"]
```

**Recommendation:** Limit node access to monitoring verbs (get, list, watch) unless node management is explicitly required.

---

## KC-009: PersistentVolume Access

**Severity:** Varies by binding scope

**Description:** Detects roles with access to `persistentvolumes` resources in the core API group. Only triggers when the apiGroup is the core group or wildcard.

**Impact:** PersistentVolumes are cluster-scoped resources. Write access can allow mounting arbitrary host paths or accessing data from other namespaces.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["persistentvolumes"]  # Triggers KC-009
  verbs: ["create", "delete"]
```

**Recommendation:** Limit PV access to read-only verbs unless storage management is required.

---

## KC-010: RBAC Modification Capability

**Severity:** Varies by binding scope

**Description:** Detects roles with access to `clusterroles` or `clusterrolebindings` resources. Only triggers when the apiGroup is `rbac.authorization.k8s.io` or wildcard.

**Impact:** Access to RBAC resources allows viewing, modifying, or creating roles and bindings, which is the foundation for privilege escalation attacks.

**Example:**

```yaml
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles", "clusterrolebindings"]  # Triggers KC-010
  verbs: ["get", "list"]
```

**Recommendation:** Limit RBAC modification to dedicated admin roles with proper audit trails.

---

## KC-011: Privilege Escalation via Role/Binding Modification

**Severity:** Varies by binding scope

**Description:** Detects roles that combine mutation verbs (`create`, `patch`, `update`) with RBAC resources (`roles`, `clusterroles`, `rolebindings`, `clusterrolebindings`). Only triggers when apiGroups include `rbac.authorization.k8s.io` or wildcard.

**Impact:** The ability to create or modify roles and bindings is the most direct path to privilege escalation. A principal can create a new ClusterRole with cluster-admin permissions and bind it to themselves.

**Example:**

```yaml
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings", "rolebindings"]  # Triggers KC-011
  verbs: ["create", "patch"]
```

**Recommendation:** Restrict ability to create/modify roles and bindings to admin users only.

---

## KC-012: Privilege Escalation via Workload Creation

**Severity:** Varies by binding scope

**Description:** Detects roles that grant `create` (or `*`) verb on workload resources: `pods`, `deployments`, `daemonsets`, `statefulsets`, `jobs`, `cronjobs`, and `replicasets`. Checks apiGroups to ensure the detection is accurate (core group for pods, `apps` for deployments/daemonsets/statefulsets/replicasets, `batch` for jobs/cronjobs).

**Impact:** The ability to create workloads allows a principal to launch pods with arbitrary service accounts, effectively assuming the permissions of any service account in the namespace.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["pods"]  # Triggers KC-012
  verbs: ["create"]
```

```yaml
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]  # Also triggers KC-012
  verbs: ["create"]
```

**Recommendation:** Restrict workload creation to CI/CD pipelines and use PodSecurity admission to constrain workload capabilities.

---

## KC-013: Pod Running with Cluster-Admin Privileges

**Severity:** CRITICAL

**Description:** Detects Pods or workload controllers whose ServiceAccount is bound to `cluster-admin` via a ClusterRoleBinding. Performs chain analysis: Pod/Workload -> ServiceAccount -> ClusterRoleBinding -> cluster-admin ClusterRole.

**Impact:** Pods running with cluster-admin have full administrative access to the cluster. A container compromise gives the attacker unrestricted control over all cluster resources.

**Example:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
subjects:
- kind: ServiceAccount
  name: admin-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin  # Triggers KC-013 when a Pod uses admin-sa
  apiGroup: rbac.authorization.k8s.io
```

**Recommendation:** Never use cluster-admin for pod service accounts. Create a scoped role with only the permissions the workload requires.

---

## KC-014: RoleBinding Referencing ClusterRole

**Severity:** WARNING

**Description:** Detects RoleBindings that reference a ClusterRole instead of a namespace-scoped Role. This fires at the RoleBinding level regardless of whether a matching Pod or workload is present. When a Pod or workload is co-located, the finding description includes which workload uses the referenced ServiceAccount.

**Impact:** While a RoleBinding scopes the ClusterRole's permissions to the binding's namespace, this pattern can be misleading. The ClusterRole may grant permissions beyond what was intended for the specific namespace. It also creates a dependency on a cluster-scoped resource for namespace-level access control.

**Example:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: my-binding
  namespace: prod
roleRef:
  kind: ClusterRole  # Triggers KC-014
  name: my-clusterrole
  apiGroup: rbac.authorization.k8s.io
```

**Recommendation:** Use a namespace-scoped Role instead of ClusterRole when granting namespace-scoped access. This improves clarity and reduces the blast radius of role modifications.

---

## KC-015: Aggregated ClusterRole Detected

**Severity:** INFO

**Description:** Detects ClusterRoles that use an `aggregationRule` field. Aggregated ClusterRoles automatically inherit permissions from other ClusterRoles matching the aggregation label selectors.

**Impact:** Aggregation rules can unintentionally inherit dangerous permissions from other ClusterRoles if the label selectors are overly broad or if new ClusterRoles with matching labels are created later.

**Example:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aggregated-role
aggregationRule:  # Triggers KC-015
  clusterRoleSelectors:
  - matchLabels:
      rbac.example.com/aggregate: "true"
```

**Recommendation:** Review aggregation labels to ensure only intended roles are included. Use specific label selectors.

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

---

## Next Steps

- [Understanding Findings](../guides/findings.md): Learn how to interpret and act on findings
- [Suppressions](../guides/suppressions.md): Suppress accepted risks or false positives
- [CLI Reference](cli.md): Control severity thresholds and output formats
