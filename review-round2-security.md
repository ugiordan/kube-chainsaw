# kube-chainsaw Round 2 Security Review

Date: 2026-05-29
Scope: Verification of 17 round 1 fixes, plus detection of new issues introduced by fixes
Reviewer: Security (adversarial)

---

## Round 1 Fix Verification

### Finding 1 (KC-014 only fires with co-located Pod) - FIXED

The fix adds a standalone loop at lines 282-294 of `analyzer.go` that iterates over all `RoleBindings` and fires KC-014 whenever `roleRef.kind == "ClusterRole"`, independent of Pod existence. The pod-enriched version at lines 262-278 still fires when a Pod/Workload is present and adds SA context to the description. Both code paths use `appendIfNew` with fingerprint dedup, so when both fire for the same RoleBinding, only one finding is emitted (the first one encountered, which is the pod-enriched version). Correct behavior.

**Status: VERIFIED FIXED**

### Finding 2 (Documentation rule IDs do not match code) - FIXED

`site/docs/reference/rules.md` now documents all 15 rules (KC-001 through KC-015) with descriptions that match the code implementation exactly. KC-006 is documented as "Secrets Access", KC-007 as "Pod Exec/Attach Access", KC-012 includes workload controllers, etc. All rule titles match `ruleDescriptions` in `rules.go`.

**Status: VERIFIED FIXED**

### Finding 3 (No apiGroup filtering) - FIXED

`apiGroupMatchesResource()` in `rules.go` now checks whether the resource belongs to `coreGroupResources` (requiring `apiGroups: [""]` or `"*"`) or `rbacGroupResources` (requiring `apiGroups: ["rbac.authorization.k8s.io"]` or `"*"`). The `checkRules` function calls this for every dangerous resource match at line 94. Wildcard apiGroups detection is implemented at lines 59-71 of `analyzer.go` via `hasWildcardAPIGroup()`. The escalation combo functions (`hasEscalationBindingCombo`, `hasEscalationPodCombo`) also include apiGroup checks.

**Status: VERIFIED FIXED**

### Finding 4 (GitHub Action downloads binary without checksum) - FIXED

The action now downloads the archive and checksums.txt to a temp directory, extracts the expected hash with `grep`, computes the actual hash with `sha256sum`, and compares them before extracting. Fails with `::error::` annotation on mismatch.

**Status: VERIFIED FIXED (with new issue, see NEW-1 below)**

### Finding 5 (Loader does not parse workload controllers) - FIXED

`workloadKinds` map in `loader.go` includes Deployment, DaemonSet, StatefulSet, Job, CronJob, and ReplicaSet. The `categorize()` function parses these in its `default` case at lines 287-302. `extractWorkloadServiceAccountName()` correctly handles the different nesting depths (CronJob has an extra `jobTemplate` layer). `WorkloadData` struct added to models. `analyzePrivilegeChains()` iterates over `resources.Workloads` at lines 230-239.

**Status: VERIFIED FIXED (with new issue, see NEW-2 below)**

### Finding 6 (Silent file processing failures) - FIXED

`walkDir` now prints warnings to stderr via `fmt.Fprintf(os.Stderr, ...)` at line 143 instead of discarding the error.

**Status: VERIFIED FIXED**

### Finding 7 (processFile follows symlinks) - PARTIALLY FIXED

`processFile` now uses `os.Lstat` at line 156 instead of `os.Stat`, and checks for symlinks at line 162. However, `os.ReadFile` at line 170 still follows symlinks. There remains a TOCTOU window between the `os.Lstat` check and the `os.ReadFile` call where a regular file could be replaced with a symlink. The round 1 finding suggested using `os.Open` + `Fstat` on the file descriptor to eliminate this race. That was not done. For a one-shot CLI tool this is very low risk, but the fix is incomplete relative to what was recommended.

**Status: PARTIALLY FIXED (TOCTOU window remains, accepted as LOW risk)**

### Finding 8 (Map key collision silently overwrites) - FIXED

All map insertions in `categorize()` now check for key existence and emit a warning to stderr before overwriting. This applies to ClusterRoles (line 229), Roles (line 241), ServiceAccounts (line 263), Pods (line 276), and Workloads (line 291).

**Status: VERIFIED FIXED (with new issue on workload keys, see NEW-2 below)**

### Finding 9 (os.Exit(1) inside RunE) - FIXED

`RunE` now returns `errThresholdExceeded` (a sentinel error) instead of calling `os.Exit(1)`. The `main()` function uses `errors.Is(err, errThresholdExceeded)` to differentiate between threshold exits (code 1) and runtime errors (code 2). Cobra's `SilenceErrors: true` ensures the error is not wrapped by Cobra, so `errors.Is` works correctly.

**Status: VERIFIED FIXED**

### Finding 10 (escalationPodResources incomplete) - FIXED

`escalationWorkloadResources` in `rules.go` now includes `pods`, `deployments`, `daemonsets`, `statefulsets`, `jobs`, `cronjobs`, and `replicasets`. The `apiGroupMatchesEscalationWorkload` function correctly maps each resource to its apiGroup (core for pods, `apps` for deployment-family, `batch` for jobs/cronjobs).

**Status: VERIFIED FIXED**

### Finding 11 (Exit code 2 never produced) - FIXED

`main()` now differentiates: `errThresholdExceeded` produces exit code 1, all other errors (argument errors, runtime errors) produce exit code 2 with an error message to stderr.

**Status: VERIFIED FIXED**

### Finding 12 (Fingerprint does not include file path) - FIXED

`ComputeFingerprint()` in `models.go` line 69 now includes `f.File` in the hash input: `"%s|%s|%s|%s|%s"` with `RuleID, ResourceKind, ResourceName, ResourceNamespace, File`. The struct comment on line 63 also reflects this.

**Status: VERIFIED FIXED**

### Finding 13 (Suppression file has no size limit and no field validation) - FIXED

`LoadSuppressions` now checks file size against `MaxSuppressionFileSize` (1MB) at lines 36-38 before reading. After parsing, it validates that `RuleID` and `ResourceName` are non-empty for each entry at lines 52-58.

**Status: VERIFIED FIXED (with minor residual, see NEW-3 below)**

### Finding 14 (GitHub Action argument injection) - FIXED

`INPUT_FORMAT` and `INPUT_FAIL_ON` are now validated with `case` statements at lines 37-44 that only accept the known values. Unknown values produce `::error::` and exit 1.

**Status: VERIFIED FIXED (with residual, see NEW-4 below)**

### Finding 15 (No stderr warning for zero RBAC resources) - FIXED

`main.go` line 100-101 now prints `WARNING: no RBAC resources found...` to stderr when `resources.IsEmpty()` returns true.

**Status: VERIFIED FIXED**

### Finding 16 (Missing test fixtures for KC-005, KC-008, KC-009) - FIXED

Test fixture files `bind-verb.yaml`, `nodes-access.yaml`, and `pv-access.yaml` exist in `testdata/dangerous/` and are referenced in `analyzer_test.go` at lines 83, 107, and 113.

**Status: VERIFIED FIXED**

### Finding 17 (CGO_ENABLED not explicitly set) - FIXED

`.goreleaser.yaml` now includes `CGO_ENABLED=0` in the `env` block at line 6.

**Status: VERIFIED FIXED**

---

## New Issues Introduced by Fixes

### NEW-1: Checksum verification downloads both archive and checksums from the same untrusted source [MEDIUM]

**File:** `.github/action.yml`, lines 60-71

The checksum fix (finding 4) downloads both the archive and `checksums.txt` from the same GitHub release. If an attacker compromises the GitHub release (e.g., via stolen deploy token, supply chain attack on goreleaser), they can replace both the binary and the checksums file simultaneously. The checksum verification then passes against the attacker's own checksum. This is a same-origin integrity check, not a trust boundary verification.

To provide real security, the checksums file should be signed (e.g., with cosign or GPG) and the signature verified against a pinned public key. Alternatively, hard-code expected hashes in the action definition for each version.

Additionally, line 65 (`grep "linux_amd64.tar.gz"`) could match multiple lines if the release contains multiple archives with `linux_amd64.tar.gz` in the name. If `grep` returns multiple lines, `awk '{print $1}'` on the first line's hash would work, but the grep should be anchored to the exact filename to be robust.

Also, if `EXPECTED_HASH` is empty (checksums.txt download failed silently, or grep matched nothing), the comparison `"" != "${ACTUAL_HASH}"` would correctly fail, but the error message would be confusing ("Expected: , Got: ..."). A guard checking that `EXPECTED_HASH` is non-empty would improve the error reporting.

### NEW-2: Workload map key does not include Kind, causing cross-kind collisions [MEDIUM]

**File:** `pkg/loader/loader.go`, lines 290-301

The fix for finding 5 stores workloads in `result.Workloads` using key `namespace/name`. Kubernetes allows different resource kinds to share the same name within a namespace (e.g., a Deployment named "nginx" and a DaemonSet named "nginx" can coexist). When both are scanned, the second one silently overwrites the first. The duplicate warning from finding 8's fix will fire, but it's a false alarm since these are legitimately distinct resources.

The key should be `kind/namespace/name` (e.g., `Deployment/default/nginx`) to prevent cross-kind collisions. This requires updating both the map key construction in `categorize()` and the iteration in `analyzePrivilegeChains()`.

This is a functional correctness bug, not just a theoretical concern. Operators commonly name their Deployment and associated resources identically.

### NEW-3: Suppression validation does not warn on unknown rule IDs [LOW]

**File:** `pkg/suppression/suppression.go`, lines 52-58

The fix for finding 13 validates that `RuleID` and `ResourceName` are non-empty, which is good. However, the original finding also mentioned that typos in rule IDs (e.g., `KC-99` instead of `KC-009`) silently match nothing. The fix does not validate that `RuleID` matches a known rule. A user could have a suppression with `rule_id: KC-099` that passes validation but never suppresses anything, giving a false sense that a finding is handled.

This could be addressed by either validating against the known rule ID set, or by emitting a warning to stderr when a suppression entry matches zero findings (a "did you mean...?" check).

### NEW-4: INPUT_VERSION, INPUT_OUTPUT, and INPUT_SUPPRESSIONS are not validated in the GitHub Action [LOW]

**File:** `.github/action.yml`, lines 56-57, 80-81

The fix for finding 14 validates `INPUT_FORMAT` and `INPUT_FAIL_ON` with case statements, but `INPUT_VERSION` is interpolated directly into URLs at lines 56-57 without sanitization. While this is less exploitable than argument injection (it's used in a URL, not a command argument), a malicious version string like `v1.0.0/../../other-repo/releases/download/v1.0.0` could be used for URL path traversal on the GitHub domain.

`INPUT_OUTPUT` and `INPUT_SUPPRESSIONS` at lines 80-81 are passed to the `--output` and `--suppressions` flags. While the `--` separator protects against them being interpreted as additional flags, they can specify arbitrary file paths. If the action runs in a context where the runner workspace contains sensitive files, `--output /etc/something` could overwrite files (though the runner typically runs as a non-root user). The `--suppressions` flag could read arbitrary files and cause them to fail parsing, leaking file existence information via error messages.

### NEW-5: IsEmpty() excludes Workloads, creating inconsistent behavior [LOW]

**File:** `pkg/models/models.go`, lines 162-171

After the fix for finding 5, workloads participate in privilege chain analysis (KC-013, KC-014). However, `IsEmpty()` does not check `len(r.Workloads)`. The comment says "Workloads and Pods are not considered RBAC resources for this check." But Pods ARE included in the check (line 170). The comment is incorrect for Pods, and Workloads are excluded despite participating in the same chain analysis as Pods.

If a scan directory contains only Deployments with ServiceAccount references (but no ClusterRoles/Roles/Bindings), `IsEmpty()` returns true and the "no RBAC resources found" warning fires. This is arguably correct (there are no RBAC resources), but the asymmetry between Pods (included) and Workloads (excluded) is inconsistent and the comment is misleading.

### NEW-6: processFile TOCTOU remains between Lstat and ReadFile [LOW]

**File:** `pkg/loader/loader.go`, lines 156-170

As noted in the finding 7 verification above, the fix replaced `os.Stat` with `os.Lstat` but still uses `os.ReadFile` which opens the path by name. Between the `os.Lstat` check at line 156 and the `os.ReadFile` at line 170, the file could be replaced with a symlink pointing to a sensitive file. The round 1 recommendation to use `os.Open` + `Fstat` on the file descriptor was not implemented.

Severity is LOW because the attack requires write access to the scanned directory and a microsecond race window on a one-shot CLI tool, but the fix is incomplete relative to the recommendation.

---

## Summary

| Category | Count |
|----------|-------|
| Fully verified fixed | 14 of 17 |
| Partially fixed | 2 (findings 7, 13) |
| Fix verification blocked | 0 |
| Not fixed | 0 |
| New issues from fixes | 6 |

| New Issue | Severity | Source Fix |
|-----------|----------|-----------|
| NEW-1: Same-origin checksum verification | MEDIUM | Finding 4 fix |
| NEW-2: Workload map key missing Kind | MEDIUM | Finding 5 fix |
| NEW-3: No validation of suppression rule IDs | LOW | Finding 13 fix |
| NEW-4: Unvalidated action inputs (version, output, suppressions) | LOW | Finding 14 fix |
| NEW-5: IsEmpty() inconsistency for Workloads | LOW | Finding 5 fix |
| NEW-6: TOCTOU window in processFile | LOW | Finding 7 fix |

### Priority recommendation

NEW-2 (workload map key collision) is the highest priority new fix. It is a functional correctness bug that will cause data loss during analysis when legitimate workloads of different kinds share a name. The fix is a one-line change to the key format.

NEW-1 (same-origin checksum) is architecturally important but requires signing infrastructure (cosign/GPG) to properly address, so it is a longer-term item.
