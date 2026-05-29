# kube-chainsaw Round 2 Correctness Review

Date: 2026-05-29
Scope: Verification of 17 round 1 fixes, detection of regressions, assessment of new test/doc coverage

---

## Round 1 Fix Verification

All 17 findings from the round 1 review have been addressed. Summary of each fix status:

| Finding | Status | Notes |
|---------|--------|-------|
| 1. KC-014 requires co-located Pod | FIXED | Standalone RoleBinding-level detection added at analyzer.go:282-294. Pod/Workload-enriched variant still fires when applicable. `appendIfNew` deduplicates correctly via fingerprint. |
| 2. Doc rule IDs mismatch code | FIXED | rules.md rewritten with all 15 rules accurately matching code. Each rule description, severity, example, and recommendation verified. |
| 3. No apiGroup filtering | FIXED | `apiGroupMatchesResource`, `apiGroupMatchesEscalationBinding`, `apiGroupMatchesEscalationWorkload` added in rules.go. `coreGroupResources` and `rbacGroupResources` maps correctly classify resources. Wildcard apiGroup detection via `hasWildcardAPIGroup` added. |
| 4. GitHub Action no checksum | FIXED | action.yml downloads checksums.txt, verifies SHA256 before extraction. Input validation added for format and fail-on. |
| 5. Loader doesn't parse workloads | FIXED | `workloadKinds` map, `extractWorkloadServiceAccountName`, `WorkloadData` model, and `Workloads` map all added. CronJob nested path handled. Analyzer walks workloads in `analyzePrivilegeChains`. |
| 6. Silent file processing failures | FIXED | `walkDir` logs errors to stderr. |
| 7. processFile follows symlinks | FIXED | Uses `os.Lstat` and checks for symlinks. |
| 8. Map key collision | FIXED | Duplicate warnings emitted to stderr for all map-stored resources. |
| 9. os.Exit inside RunE | FIXED | Sentinel errors `errThresholdExceeded` and `errRuntime`. `main()` handles exit codes. |
| 10. escalationPodResources incomplete | FIXED | Renamed to `escalationWorkloadResources`, expanded with 6 additional workload types. |
| 11. Exit code 2 never produced | FIXED | `main()` exits 2 for non-threshold errors. CLI tests verify both exit codes. |
| 12. Fingerprint without file path | FIXED | `ComputeFingerprint` includes `f.File`. Test verifies different files produce different fingerprints. |
| 13. Suppression no size limit | FIXED | 1MB limit, size check, field validation. Tests cover all three. |
| 14. GitHub Action argument injection | FIXED | `case` statement validation for format and fail-on inputs. |
| 15. No stderr warning for zero RBAC | FIXED | main.go:100-101 emits warning. |
| 16. Missing test fixtures KC-005/008/009 | FIXED | bind-verb.yaml, nodes-access.yaml, pv-access.yaml added. Table-driven test entries cover all. |
| 17. CGO_ENABLED not explicit | FIXED | `.goreleaser.yaml` line 7: `CGO_ENABLED=0`. |

---

## New Findings

### R2-1. Zero test coverage for workload parsing and workload chain analysis [MEDIUM]

**Files:** `pkg/loader/loader.go` (lines 287-303, 367-399), `pkg/analyzer/analyzer.go` (lines 229-238), `testdata/`

**Description:** The workload parsing path added for finding 5 has zero YAML fixture coverage. No Deployment, DaemonSet, StatefulSet, Job, CronJob, or ReplicaSet manifests exist in `testdata/`. This means:

1. `extractWorkloadServiceAccountName` is completely untested with real YAML (all four nesting levels: Deployment path, Job path, CronJob nested path, and the "no SA defaults to default" fallback).
2. The KC-013 chain analysis for workloads (e.g., Deployment -> SA -> cluster-admin ClusterRoleBinding) has no integration test.
3. The CronJob's doubly-nested spec path (`spec.jobTemplate.spec.template.spec.serviceAccountName`) is the most complex extraction path and is untested.
4. `loader_test.go` has zero assertions on `result.Workloads`.

A regression in the YAML traversal logic (e.g., typo in a field name, wrong nesting level) would go undetected by the test suite.

**Impact:** The workload feature advertised in KC-012 and KC-013 descriptions works in-memory but has no end-to-end validation. A bug in YAML parsing would silently miss workload-based privilege escalation chains.

**Recommendation:** Add at minimum: (a) a `testdata/dangerous/deployment-cluster-admin.yaml` with a Deployment -> SA -> ClusterRoleBinding -> cluster-admin chain, (b) a `testdata/dangerous/cronjob-cluster-admin.yaml` to cover the CronJob nested path, (c) assertions in `loader_test.go` that `result.Workloads` is populated with correct SA names.

### R2-2. `IsEmpty()` comment contradicts implementation regarding Pods [LOW]

**File:** `pkg/models/models.go`, lines 163-171

**Description:** The comment says "Workloads and Pods are not considered RBAC resources for this check" but the implementation checks `len(r.Pods) == 0`. A directory containing only Pod manifests (no roles, bindings, or SAs) would not trigger the "WARNING: no RBAC resources found" stderr message, even though Pods without RBAC context are not meaningful for the analyzer.

This is internally inconsistent. Workloads are excluded from the check but Pods are included, despite Pods being no more "RBAC" than Deployments.

**Impact:** Misleading comment. The behavioral impact is minor: a directory with only Pods would produce no findings but also no warning, which could be confusing. Not a release blocker on its own, but the comment should match the code.

**Recommendation:** Either update the comment to say "Workloads are not considered RBAC resources for this check" (removing the Pods mention), or add `len(r.Workloads) == 0` to `IsEmpty()` for consistency.

---

## Items Verified as Not Blocking

The following were examined and determined to not be release blockers:

- **Duplicate KC-001 findings for roles with both wildcard apiGroups and wildcard resources.** A role with `apiGroups: ["*"]` and `resources: ["*"]` produces two KC-001 findings (one from `hasWildcardAPIGroup`, one from `dangerousResources["*"]`). They share the same fingerprint, so suppressions cover both with a single entry. Both findings are semantically valid. Edge case, not a release blocker.

- **`resources: ["*"]` in KC-011/KC-012 bypasses apiGroup checks.** `hasEscalationPodCombo` and `hasEscalationBindingCombo` return true for `resources: ["*"]` regardless of apiGroup. This is consistent with how KC-001 treats wildcard resources (also apiGroup-independent). Defensively correct for security tooling.

- **GitHub Action `sha256sum` is Linux-only.** The action uses `sha256sum` which doesn't exist on macOS. Since composite actions inherit the caller's runner, a macOS-based workflow would fail. However, the tool name says "linux_amd64" in the download URL, so macOS usage is unsupported regardless. Not a new issue from the fixes.

- **docs/code alignment.** All 15 rule descriptions in rules.md accurately match the code implementation, including severity model, special cases, apiGroup filtering behavior, and workload resource list.

---

## Conclusion

Of the 17 round 1 findings, all have been properly fixed with no regressions introduced to the existing test suite. The fixes are structurally sound.

One finding (R2-1) is MEDIUM severity and should be addressed before v0.1.0: the workload feature has no end-to-end test coverage, meaning the CronJob and Deployment SA extraction paths could break silently. The LOW finding (R2-2) is a comment/code inconsistency that should be fixed but does not block release.
