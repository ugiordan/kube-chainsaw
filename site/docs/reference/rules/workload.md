# Workload and OpenShift Rules

These rules inspect declared workload security contexts and OpenShift SecurityContextConstraints assignments.

| Rules | Focus |
|---|---|
| [KC-019](#kc-019-privileged-container-requested) | Privileged containers |
| [KC-020](#kc-020-host-namespace-access-requested) | Host network, PID, and IPC namespaces |
| [KC-021](#kc-021-hostpath-volume-requested) | Mounted hostPath volumes |
| [KC-022](#kc-022-dangerous-linux-capability-requested) | Dangerous Linux capabilities |
| [KC-023](#kc-023-openshift-securitycontextconstraints-use-permission) | RBAC SCC `use` permissions |
| [KC-024](#kc-024-permissive-openshift-securitycontextconstraints-assignment) | Directly assigned permissive SCCs |

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

Built-in permissive SCCs without direct subjects are not reported by KC-024. Review their RBAC `use` permissions with KC-023 instead.

See the runnable examples in [`examples/security/`](https://github.com/ugiordan/kube-chainsaw/tree/main/examples/security).

---

## Next Steps

- [Detection Rules Overview](../rules.md)
- [Understanding Findings](../../guides/findings.md)
- [Suppressions](../../guides/suppressions.md)
