# Plugin System

kube-chainsaw offers an optional paid addon for Kubernetes secret analysis and runtime RBAC correlation.

---

## Overview

The open-source version of kube-chainsaw analyzes RBAC manifests statically. The paid plugin adds:

- **Secret content analysis**: Detect hardcoded credentials in Kubernetes Secrets
- **Runtime correlation**: Compare static manifests against live cluster RBAC state
- **Custom rules**: Add organization-specific detection patterns
- **Advanced reporting**: Enhanced SARIF output with compliance mappings (CIS, NSA/CISA)

---

## Installation

The plugin is distributed as a separate Python package:

```bash
pip install kube-chainsaw-plugin
```

Verify installation:

```bash
kube-chainsaw --version
# Output: kube-chainsaw 1.0.0 (plugin: enabled)
```

---

## Secret Analysis

Enable secret scanning:

```bash
kube-chainsaw scan k8s/ --plugin-secrets
```

**Detected patterns:**

- Base64-encoded AWS access keys
- Hardcoded database passwords
- API tokens and service account keys
- TLS private keys in plaintext

**Example output:**

```
[CRITICAL] PLUGIN-SEC-001: Hardcoded AWS access key in Secret 'db-credentials'
  Location: secrets/db.yaml:7:5
  Impact: Credential leak if manifest is committed to version control
  Recommendation: Use external secret managers (Vault, AWS Secrets Manager)
```

---

## Runtime Correlation

Compare manifests against a live cluster:

```bash
kube-chainsaw scan k8s/ --plugin-runtime --kubeconfig ~/.kube/config
```

**Detected drift:**

- Roles defined in manifests but not applied to the cluster
- Live ClusterRoleBindings not present in version control
- ServiceAccounts with runtime permissions exceeding manifest definitions

**Example output:**

```
[HIGH] PLUGIN-DRIFT-002: ClusterRoleBinding 'admin-binding' exists in cluster but not in manifests
  Impact: Untracked admin access may violate security policies
  Recommendation: Add to version control or remove from cluster
```

---

## Custom Rules

Define organization-specific rules in `kube-chainsaw-custom-rules.yaml`:

```yaml
rules:
  - id: CUSTOM-001
    name: "Disallow ServiceAccounts with 'admin' prefix"
    severity: high
    pattern:
      kind: ServiceAccount
      metadata:
        name: "^admin-.*"
    message: "ServiceAccounts must not use 'admin' prefix per security policy SEC-2024-15"
```

Run with custom rules:

```bash
kube-chainsaw scan k8s/ --custom-rules kube-chainsaw-custom-rules.yaml
```

---

## Enhanced SARIF

The plugin adds compliance tags to SARIF output:

```json
{
  "ruleId": "KC-001",
  "properties": {
    "tags": [
      "CIS-1.5.1",
      "NSA-CISA-K8S-1.2"
    ]
  }
}
```

These tags enable compliance reporting in security platforms.

---

## Licensing

The plugin requires a license key:

```bash
export KUBE_CHAINSAW_LICENSE_KEY="your-key-here"
kube-chainsaw scan k8s/ --plugin-secrets
```

Or pass via CLI:

```bash
kube-chainsaw scan k8s/ --license-key your-key-here --plugin-secrets
```

**Pricing:**

- **Individual**: $99/year (single user)
- **Team**: $499/year (up to 10 users)
- **Enterprise**: Custom pricing (unlimited users, support SLA)

Contact [sales@kube-chainsaw.dev](mailto:sales@kube-chainsaw.dev) for trial licenses.

---

## Roadmap

Upcoming plugin features (2027 Q3):

- **OPA/Rego integration**: Custom policy enforcement
- **RBAC graph visualization**: Interactive HTML reports
- **Multi-cluster analysis**: Compare RBAC across dev/staging/prod clusters
- **Automated remediation**: Generate pull requests to fix findings

---

## Next Steps

- [Detection Rules](../reference/rules.md): Core rules included in the open-source version
- [CLI Reference](../reference/cli.md): All command-line options
- [CI Integration](ci-integration.md): Use the plugin in GitHub Actions or GitLab CI
