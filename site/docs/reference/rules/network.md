# Network and Exposure Rules

These rules cover NetworkPolicy scope and declared network entry points. They report manifest intent, not effective reachability through a CNI, load balancer, or external proxy.

| Rules | Focus |
|---|---|
| [KC-016](#kc-016-networkpolicy-access) | RBAC access to NetworkPolicies |
| [KC-017](#kc-017-networkpolicy-allows-ingress-from-broad-peers) | Broad ingress peers |
| [KC-018](#kc-018-networkpolicy-allows-egress-to-broad-destinations) | Broad egress peers |
| [KC-025](#kc-025-external-service-exposure) | LoadBalancer, NodePort, ExternalName, and external IP declarations |
| [KC-026](#kc-026-unencrypted-external-route) | Missing TLS or plaintext Route policy |
| [KC-027](#kc-027-broad-external-route) | Catch-all, wildcard, and subdomain routing |

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

See the runnable examples in [`examples/networkpolicy/`](https://github.com/ugiordan/kube-chainsaw/tree/main/examples/networkpolicy) and [`examples/exposure/`](https://github.com/ugiordan/kube-chainsaw/tree/main/examples/exposure).

---

## Next Steps

- [Detection Rules Overview](../rules.md)
- [Understanding Findings](../../guides/findings.md)
- [Suppressions](../../guides/suppressions.md)
