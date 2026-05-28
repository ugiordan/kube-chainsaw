# Detection Rules

kube-chainsaw implements 15 static analysis rules to detect RBAC misconfigurations and privilege escalation paths.

---

## KC-001: Wildcard Verbs

**Severity:** HIGH

**Description:** Detects `verbs: ["*"]` in Role or ClusterRole rules.

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
  verbs: ["*"]  # ❌ Wildcard verbs
```

**Recommendation:** Replace `*` with explicit verbs:

```yaml
verbs: ["get", "list", "watch"]
```

---

## KC-002: Wildcard Resources

**Severity:** HIGH

**Description:** Detects `resources: ["*"]` in Role or ClusterRole rules.

**Impact:** Grants access to all resource types in the API group, including secrets, configmaps, and service accounts.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["*"]  # ❌ Wildcard resources
  verbs: ["get"]
```

**Recommendation:** List explicit resources:

```yaml
resources: ["pods", "services", "endpoints"]
```

---

## KC-003: Cluster-Admin Binding

**Severity:** CRITICAL

**Description:** Detects ClusterRoleBindings to the built-in `cluster-admin` ClusterRole.

**Impact:** Grants full administrative access to the entire cluster, including the ability to create, modify, and delete any resource.

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
  name: cluster-admin  # ❌ Binds to cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

**Recommendation:** Create a scoped Role with only required permissions.

---

## KC-004: Default ServiceAccount with Elevated Permissions

**Severity:** HIGH

**Description:** Detects RoleBindings or ClusterRoleBindings to the `default` ServiceAccount in any namespace.

**Impact:** Every pod in the namespace inherits these permissions unless explicitly overridden, violating least privilege.

**Example:**

```yaml
subjects:
- kind: ServiceAccount
  name: default  # ❌ Binding to default SA
  namespace: kube-system
```

**Recommendation:** Create a dedicated ServiceAccount:

```yaml
subjects:
- kind: ServiceAccount
  name: my-app-sa
  namespace: kube-system
```

---

## KC-005: System ServiceAccount Binding

**Severity:** MEDIUM

**Description:** Detects bindings to ServiceAccounts in the `kube-system` namespace or with names starting with `system:`.

**Impact:** System ServiceAccounts are intended for cluster components. Binding workloads to them violates separation of concerns.

**Example:**

```yaml
subjects:
- kind: ServiceAccount
  name: system:kube-proxy  # ❌ System ServiceAccount
  namespace: kube-system
```

**Recommendation:** Use application-specific ServiceAccounts.

---

## KC-006: Wildcard API Groups

**Severity:** HIGH

**Description:** Detects `apiGroups: ["*"]` in Role or ClusterRole rules.

**Impact:** Grants access to all current and future API groups, including custom resources.

**Example:**

```yaml
rules:
- apiGroups: ["*"]  # ❌ Wildcard API groups
  resources: ["pods"]
  verbs: ["get"]
```

**Recommendation:** List explicit API groups:

```yaml
apiGroups: ["", "apps", "batch"]
```

---

## KC-007: Privilege Escalation Chain

**Severity:** CRITICAL

**Description:** Detects multi-hop privilege escalation paths through graph traversal (e.g., `pods/exec` → secret access → cluster-admin).

**Impact:** ServiceAccounts with seemingly limited permissions can escalate to cluster-admin through intermediate resources.

**Example:**

A ServiceAccount with `pods/exec` can execute commands in pods that mount service account tokens with elevated permissions, effectively escalating privileges.

**Recommendation:** Audit all ServiceAccount bindings and remove unnecessary `exec` permissions.

---

## KC-008: ServiceAccount Token Escalation

**Severity:** CRITICAL

**Description:** Detects ServiceAccounts with `create` or `patch` permissions on ServiceAccount resources.

**Impact:** Allows creation of new ServiceAccounts or modification of existing ones, enabling privilege escalation.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["create", "patch"]  # ❌ Can create/modify SAs
```

**Recommendation:** Restrict ServiceAccount management to cluster administrators.

---

## KC-009: Unbound Role

**Severity:** LOW

**Description:** Detects Roles or ClusterRoles not referenced by any RoleBinding or ClusterRoleBinding.

**Impact:** Dead code that increases attack surface if later bound without review.

**Example:**

A ClusterRole exists but no ClusterRoleBinding references it.

**Recommendation:** Delete unused roles or document why they exist.

---

## KC-010: Duplicate Rules

**Severity:** LOW

**Description:** Detects duplicate rules within a single Role or ClusterRole.

**Impact:** Indicates configuration error or copy-paste mistake. No direct security impact but reduces maintainability.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["pods"]  # ❌ Duplicate
  verbs: ["get"]
```

**Recommendation:** Remove duplicate rules.

---

## KC-011: Empty Role

**Severity:** LOW

**Description:** Detects Roles or ClusterRoles with no rules or only trivial rules (e.g., `verbs: []`).

**Impact:** Dead code with no functional purpose.

**Example:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: empty-role
rules: []  # ❌ No rules
```

**Recommendation:** Delete empty roles.

---

## KC-012: Secrets Access

**Severity:** HIGH

**Description:** Detects roles with `get`, `list`, or `watch` permissions on `secrets` resources.

**Impact:** Allows exfiltration of credentials, tokens, and other sensitive data.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]  # ❌ Secret access
  verbs: ["get", "list"]
```

**Recommendation:** Grant secret access only to administrators and operators that require it.

---

## KC-013: Cross-Namespace Binding

**Severity:** MEDIUM

**Description:** Detects RoleBindings where the subject namespace differs from the binding namespace.

**Impact:** Cross-namespace bindings can violate namespace isolation policies.

**Example:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cross-ns-binding
  namespace: prod
subjects:
- kind: ServiceAccount
  name: dev-sa
  namespace: dev  # ❌ Subject in different namespace
roleRef:
  kind: Role
  name: prod-role
  apiGroup: rbac.authorization.k8s.io
```

**Recommendation:** Create dedicated ServiceAccounts in each namespace.

---

## KC-014: Pods Exec Permission

**Severity:** HIGH

**Description:** Detects roles with `create` verb on `pods/exec` subresource.

**Impact:** Allows execution of arbitrary commands in running pods, potentially leading to container escape or credential theft.

**Example:**

```yaml
rules:
- apiGroups: [""]
  resources: ["pods/exec"]  # ❌ Exec permission
  verbs: ["create"]
```

**Recommendation:** Grant `pods/exec` only to operators and CI/CD systems that require it.

---

## KC-015: Role Aggregation Misconfiguration

**Severity:** MEDIUM

**Description:** Detects ClusterRoles with `aggregationRule` that select overly broad labels.

**Impact:** Aggregation rules can unintentionally inherit dangerous permissions from other ClusterRoles.

**Example:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aggregated-role
aggregationRule:
  clusterRoleSelectors:
  - matchLabels:
      app: "*"  # ❌ Overly broad selector
```

**Recommendation:** Use specific label selectors for aggregation.

---

## Rule Severity Summary

| Severity | Rules |
|----------|-------|
| CRITICAL | KC-003, KC-007, KC-008 |
| HIGH | KC-001, KC-002, KC-004, KC-006, KC-012, KC-014 |
| MEDIUM | KC-005, KC-013, KC-015 |
| LOW | KC-009, KC-010, KC-011 |

---

## Next Steps

- [Understanding Findings](../guides/findings.md): Learn how to interpret and act on findings
- [Suppressions](../guides/suppressions.md): Suppress accepted risks or false positives
- [CLI Reference](cli.md): Control severity thresholds and output formats
