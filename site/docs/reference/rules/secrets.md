# Secrets and Certificate Rules

These rules identify credential material and permissions that can mint or approve trusted identities.

| Rules | Focus |
|---|---|
| [KC-028](#kc-028-credential-material-in-secret-manifest) | Credential-bearing static Secret manifests |
| [KC-029](#kc-029-long-lived-serviceaccount-token-secret) | Long-lived ServiceAccount token Secrets |
| [KC-030](#kc-030-serviceaccount-token-minting-permission) | `serviceaccounts/token` creation permissions |
| [KC-031](#kc-031-certificatesigningrequest-approval-or-signing-permission) | CSR approval and signing permissions |

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

Secret payloads are never included in findings. Live-cluster scans do not fetch Secret objects, so KC-028 and KC-029 are static-manifest checks.

See the runnable examples in [`examples/security/`](https://github.com/ugiordan/kube-chainsaw/tree/main/examples/security).

---

## Next Steps

- [Detection Rules Overview](../rules.md)
- [Understanding Findings](../../guides/findings.md)
- [Suppressions](../../guides/suppressions.md)
