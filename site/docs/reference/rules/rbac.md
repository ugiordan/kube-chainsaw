# RBAC and Privilege Rules

These rules cover broad permissions, dangerous verbs, privilege chains, and workload creation paths.

| Rules | Focus |
|---|---|
| [KC-001](../rules.md#kc-001-wildcard-resource-access), [KC-002](../rules.md#kc-002-wildcard-verb-access) | Wildcard resources and verbs |
| [KC-003](../rules.md#kc-003-escalate-verb-permission) to [KC-005](../rules.md#kc-005-bind-verb-permission) | `escalate`, `impersonate`, and `bind` |
| [KC-006](../rules.md#kc-006-secrets-access) to [KC-010](../rules.md#kc-010-rbac-modification-capability) | Sensitive resources and administrative access |
| [KC-011](../rules.md#kc-011-privilege-escalation-via-rolebinding-modification), [KC-012](../rules.md#kc-012-privilege-escalation-via-workload-creation) | Escalation combinations |
| [KC-013](../rules.md#kc-013-pod-running-with-cluster-admin-privileges) to [KC-015](../rules.md#kc-015-aggregated-clusterrole-detected) | Privilege chains and aggregated roles |

Use the [full rule reference](../rules.md) for severity, examples, impact, and remediation details.
