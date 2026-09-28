# Network and Exposure Rules

These rules cover NetworkPolicy scope and declared network entry points. They report manifest intent, not effective reachability through a CNI, load balancer, or external proxy.

| Rules | Focus |
|---|---|
| [KC-016](../rules.md#kc-016-networkpolicy-access) | RBAC access to NetworkPolicies |
| [KC-017](../rules.md#kc-017-networkpolicy-allows-ingress-from-broad-peers) | Broad ingress peers |
| [KC-018](../rules.md#kc-018-networkpolicy-allows-egress-to-broad-destinations) | Broad egress peers |
| [KC-025](../rules.md#kc-025-external-service-exposure) | LoadBalancer, NodePort, ExternalName, and external IP declarations |
| [KC-026](../rules.md#kc-026-unencrypted-external-route) | Missing TLS or plaintext Route policy |
| [KC-027](../rules.md#kc-027-broad-external-route) | Catch-all, wildcard, and subdomain routing |

See the runnable examples in [`examples/networkpolicy/`](https://github.com/ugiordan/kube-chainsaw/tree/main/examples/networkpolicy) and [`examples/exposure/`](https://github.com/ugiordan/kube-chainsaw/tree/main/examples/exposure).
