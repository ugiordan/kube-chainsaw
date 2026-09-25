# NetworkPolicy examples

These manifests are runnable examples for the NetworkPolicy rules.

Scan the restricted example:

```bash
kube-chainsaw examples/networkpolicy/secure.yaml
```

It contains a namespace-wide default deny policy and explicit pod, namespace, port, and CIDR-free peers. It should produce no NetworkPolicy findings.

Scan the intentionally broad example:

```bash
kube-chainsaw examples/networkpolicy/broad.yaml --fail-on WARNING
```

It demonstrates:

- `KC-016`: RBAC access to NetworkPolicies
- `KC-017`: ingress from all sources
- `KC-018`: egress to all IP addresses

The broad example omits `policyTypes` on the egress policy to demonstrate Kubernetes defaulting behavior.
