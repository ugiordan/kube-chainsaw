# Workload security examples

These examples exercise pod security-context and OpenShift SCC checks.

Scan the Kubernetes workload example:

```bash
kube-chainsaw examples/security/workload.yaml --fail-on WARNING
```

It demonstrates privileged mode, host namespaces, a sensitive `hostPath`, and a dangerous Linux capability.

Scan the OpenShift example on an OpenShift manifest set:

```bash
kube-chainsaw examples/security/scc.yaml --fail-on WARNING
```

It demonstrates an SCC granted to `system:authenticated` and an RBAC `use` permission for that SCC.

Static Secret examples are in `examples/security/secrets.yaml`. Live-cluster scans intentionally do not fetch Secret payloads.

The restricted counterpart is `examples/security/secure.yaml` and should produce no workload, SCC, Secret, or token findings.

RBAC token and CSR examples are in `examples/security/rbac-sensitive.yaml`. The restricted token-reader role is included in `examples/security/secure.yaml`.
