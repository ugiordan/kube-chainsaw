# Detection Rules

kube-chainsaw implements 31 static analysis rules to detect RBAC misconfigurations, privilege escalation paths, broad NetworkPolicy peers, dangerous workload settings, external exposure, credential manifests, and OpenShift SCC risks.

## Rule Groups

Use the sidebar to browse rules by security area:

| Group | Rules |
|---|---|
| [RBAC and Privileges](rules/rbac.md) | KC-001 to KC-015 |
| [Network and Exposure](rules/network.md) | KC-016 to KC-018, KC-025 to KC-027 |
| [Workloads and OpenShift](rules/workload.md) | KC-019 to KC-024 |
| [Secrets and Certificates](rules/secrets.md) | KC-028 to KC-031 |

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

## KC-007: Dangerous Pod Subresource Access

**Severity:** Varies by binding scope

**Description:** Detects roles with access to dangerous pod subresources in the core API group: `pods/exec`, `pods/attach`, `pods/log`, and `pods/ephemeralcontainers`. Only triggers when the apiGroup is the core group or wildcard.

**Impact:**

- `pods/exec`: remote code execution inside running containers
- `pods/attach`: interactive shell access to container processes
- `pods/log`: exfiltration of log data from any pod (may contain secrets, tokens, PII)
- `pods/ephemeralcontainers`: injection of debug containers into running pods

When granted cluster-wide, a compromised ServiceAccount can access pods in any namespace, not just the namespaces the operator manages.

**Examples:**

```yaml
rules:
- apiGroups: [""]
  resources: ["pods/exec"]  # Triggers KC-007
  verbs: ["create"]
```

```yaml
rules:
- apiGroups: [""]
  resources: ["pods/log"]  # Triggers KC-007
  verbs: ["get"]
```

**Recommendation:** Restrict pod subresource access (exec, attach, log, ephemeralcontainers) to specific namespaces and add audit logging. Use namespace-scoped Roles instead of ClusterRoles when possible.

---

## KC-008: Node-Level Access

**Severity:** Varies by binding scope

**Description:** Detects roles with access to `nodes` or `nodes/proxy` resources in the core API group. Only triggers when the apiGroup is the core group or wildcard.

**Impact:** Grants access to node-level operations. Write access to nodes can allow modification of node labels, taints, and conditions. `nodes/proxy` grants direct access to the Kubelet API on any node, enabling pod listing, log reading, and command execution at the node level, bypassing RBAC entirely.

**Examples:**

```yaml
rules:
- apiGroups: [""]
  resources: ["nodes"]  # Triggers KC-008
  verbs: ["get", "list", "watch", "update"]
```

```yaml
rules:
- apiGroups: [""]
  resources: ["nodes/proxy"]  # Triggers KC-008
  verbs: ["get", "create"]
```

**Recommendation:** Limit node and node/proxy access to monitoring verbs (get, list, watch) unless node management is explicitly required. Never grant nodes/proxy unless the component requires direct Kubelet API access.

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

## KC-016: NetworkPolicy Access

**Severity:** Varies by binding scope

**Description:** Detects Roles and ClusterRoles with access to `networkpolicies` in the `networking.k8s.io` API group. Wildcard API groups also trigger this rule.

**Impact:** A principal that can modify NetworkPolicies may disable network isolation or add paths to sensitive workloads. Read access can also expose the cluster's network segmentation design.

**Example:**

```yaml
rules:
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]  # Triggers KC-016
  verbs: ["get", "update"]
```

**Recommendation:** Restrict NetworkPolicy access to the small set of operators responsible for network isolation, and audit policy changes.

---

## KC-017: NetworkPolicy Allows Ingress from Broad Peers

**Severity:** HIGH when the policy selects all pods in its namespace, otherwise WARNING

**Description:** Detects ingress rules that omit peer selectors, use an empty peer list, select pods in all namespaces, or allow all IP addresses with `0.0.0.0/0` or `::/0`.

**Impact:** Broad ingress peers can expose workloads to unintended namespaces, pods, or external sources. The finding is policy-level and does not claim that every selected port is reachable at runtime.

**Example:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
  - {}  # Triggers KC-017
```

**Recommendation:** Use explicit `podSelector`, `namespaceSelector`, or `ipBlock` peers and limit ports to the traffic the workload requires.

---

## KC-018: NetworkPolicy Allows Egress to Broad Destinations

**Severity:** HIGH when the policy selects all pods in its namespace, otherwise WARNING

**Description:** Detects egress rules that omit destination selectors, use an empty destination list, select pods in all namespaces, or allow all IP addresses with `0.0.0.0/0` or `::/0`.

**Impact:** Broad egress destinations let workloads contact unintended namespaces or external endpoints. The finding is policy-level and does not calculate effective connectivity across multiple additive policies or network plugins.

**Example:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-public-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: worker
  policyTypes: [Egress]
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0  # Triggers KC-018
```

**Recommendation:** Restrict egress to explicit namespaces, pods, or approved CIDRs. Add exceptions deliberately and limit ports where possible.

---

## KC-019: Privileged Container Requested

**Severity:** HIGH

**Description:** Detects containers, init containers, or ephemeral containers that explicitly request `securityContext.privileged: true`.

**Impact:** A privileged container can bypass normal container isolation and access host-level capabilities.

**Recommendation:** Remove privileged mode. If host-level access is required, isolate the workload and use the narrowest approved security policy.

---

## KC-020: Host Namespace Access Requested

**Severity:** HIGH

**Description:** Detects Pods and workload templates that enable `hostNetwork`, `hostPID`, or `hostIPC`.

**Impact:** Sharing host namespaces exposes host networking or process and IPC state to the workload.

**Recommendation:** Disable host namespace sharing unless the workload is trusted infrastructure with a documented requirement.

---

## KC-021: HostPath Volume Requested

**Severity:** WARNING or HIGH

**Description:** Detects `hostPath` volumes. Sensitive paths such as `/`, `/etc`, `/proc`, `/sys`, `/var/run`, and kubelet or container runtime directories produce HIGH findings.

**Impact:** HostPath mounts can expose host files, sockets, credentials, or container runtime state.

**Recommendation:** Prefer ConfigMaps, Secrets, PersistentVolumeClaims, or projected volumes. Restrict host paths and access when unavoidable.

---

## KC-022: Dangerous Linux Capability Requested

**Severity:** WARNING or HIGH

**Description:** Detects added capabilities such as `NET_RAW`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_ADMIN`, `SYS_MODULE`, `DAC_READ_SEARCH`, or `ALL`.

**Impact:** Added capabilities can bypass filesystem, networking, process, or kernel isolation.

**Recommendation:** Drop all unnecessary capabilities and add only the single capability required by the workload.

---

## KC-023: OpenShift SecurityContextConstraints Use Permission

**Severity:** Varies by binding scope

**Description:** Detects RBAC `use` permissions for `securitycontextconstraints` in the `security.openshift.io` API group.

**Impact:** SCC use permissions can allow a principal to request privileged containers, host namespaces, broad capabilities, or host volumes, depending on the named SCC.

**Recommendation:** Restrict `use` to named SCCs and trusted administrative identities. Avoid wildcard SCC resources and API groups.

---

## KC-024: Permissive OpenShift SecurityContextConstraints Assignment

**Severity:** HIGH for broad subjects, otherwise WARNING

**Description:** Detects permissive SCC settings assigned directly to users or groups. Unassigned built-in SCCs are not reported because their effective risk depends on RBAC `use` permissions.

**Impact:** Broad assignments such as `system:authenticated` can let most cluster users request privileged or host-integrated workloads.

**Recommendation:** Assign restrictive SCCs to narrow service accounts or groups and review privileged SCC use through RBAC.

---

## KC-025: External Service Exposure

**Severity:** WARNING

**Description:** Detects Services using `LoadBalancer`, `NodePort`, or `ExternalName`, or declaring `externalIPs`.

**Impact:** These declarations can make a Service reachable outside its cluster-internal boundary.

**Recommendation:** Restrict exposure to intentional entry points and document the required network controls.

---

## KC-026: Unencrypted External Route

**Severity:** WARNING or HIGH

**Description:** Detects Ingress or OpenShift Route declarations without TLS. Routes that set `insecureEdgeTerminationPolicy: Allow` produce HIGH findings.

**Impact:** Plaintext traffic can expose credentials and application data. This is a declared-manifest finding and does not determine whether an upstream proxy terminates TLS.

**Recommendation:** Configure TLS termination and reject or redirect plaintext traffic.

---

## KC-027: Broad External Route

**Severity:** WARNING

**Description:** Detects Ingress catch-all or wildcard hosts and OpenShift Routes with `wildcardPolicy: Subdomain`.

**Impact:** Broad host matching can route unintended domains or subdomains to a workload.

**Recommendation:** Use explicit hosts unless wildcard routing is intentional and controlled.

---

## KC-028: Credential Material in Secret Manifest

**Severity:** WARNING

**Description:** Detects credential-bearing Secret types or sensitive key names in static manifests. Secret values are never included in findings.

**Impact:** Base64 in a Secret manifest is encoding, not encryption. Repository readers or build logs may access the credential material.

**Recommendation:** Use an external Secret manager or sealed/encrypted workflow and avoid committing plaintext credential material.

---

## KC-029: Long-lived ServiceAccount Token Secret

**Severity:** HIGH

**Description:** Detects `kubernetes.io/service-account-token` Secrets and token Secrets associated with a ServiceAccount.

**Impact:** Persisted token Secrets are long-lived credentials that can survive workload rotation.

**Recommendation:** Use short-lived projected ServiceAccount tokens or the TokenRequest API instead.

---

## KC-030: ServiceAccount Token Minting Permission

**Severity:** Varies by binding scope

**Description:** Detects RBAC access to the core `serviceaccounts/token` subresource.

**Impact:** A principal with this access can request tokens for ServiceAccounts and potentially act as those identities.

**Recommendation:** Restrict `serviceaccounts/token` access to narrowly scoped automation.

---

## KC-031: CertificateSigningRequest Approval or Signing Permission

**Severity:** Varies by binding scope

**Description:** Detects RBAC permissions that can approve or sign Kubernetes CertificateSigningRequests.

**Impact:** Certificate approval or signing can create trusted client or serving identities.

**Recommendation:** Restrict CSR approval and signing to the cluster certificate controllers and administrators.

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
