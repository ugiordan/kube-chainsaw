# Exposure examples

These manifests demonstrate declared external exposure checks.

```bash
kube-chainsaw examples/exposure/external.yaml --fail-on WARNING
```

The example contains an external Service, a catch-all Ingress, and a wildcard OpenShift Route that permits plaintext traffic.

The restricted counterpart is `examples/exposure/secure.yaml` and should produce no exposure findings.
