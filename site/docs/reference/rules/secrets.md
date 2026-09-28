# Secrets and Certificate Rules

These rules identify credential material and permissions that can mint or approve trusted identities.

| Rules | Focus |
|---|---|
| [KC-028](../rules.md#kc-028-credential-material-in-secret-manifest) | Credential-bearing static Secret manifests |
| [KC-029](../rules.md#kc-029-long-lived-serviceaccount-token-secret) | Long-lived ServiceAccount token Secrets |
| [KC-030](../rules.md#kc-030-serviceaccount-token-minting-permission) | `serviceaccounts/token` creation permissions |
| [KC-031](../rules.md#kc-031-certificatesigningrequest-approval-or-signing-permission) | CSR approval and signing permissions |

Secret payloads are never included in findings. Live-cluster scans do not fetch Secret objects, so KC-028 and KC-029 are static-manifest checks.

See the runnable examples in [`examples/security/`](https://github.com/ugiordan/kube-chainsaw/tree/main/examples/security).
