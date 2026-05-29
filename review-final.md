# kube-chainsaw Adversarial Code Review: Final Report

Date: 2026-05-29
Reviewers: Security, Architecture, Correctness, Red Team
Scope: Full source review of kube-chainsaw Go codebase

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 3     |
| MEDIUM   | 6     |
| LOW      | 8     |
| Total    | 17    |

This report consolidates findings from four independent review passes. Duplicates have been merged (5 issues were reported 13 times across reviewers). Severities have been adjusted per red team challenge. Two findings were removed for weak evidence. Six blind spots identified by the red team have been added as new findings.

---

## Must Fix Before v0.1.0

### 1. KC-014 only fires when a Pod is co-located in the same manifest set [HIGH]

**File:** `pkg/analyzer/analyzer.go`, lines 196-215

`analyzePrivilegeChains()` iterates over `resources.Pods` and only emits KC-014 when a Pod exists that uses the SA referenced by the RoleBinding. If the RoleBinding and Pod are in different files or repos (the common case in production), KC-014 never fires, producing false negatives on a core detection rule. Fix by iterating over all RoleBindings that reference ClusterRoles independently of Pod existence.

### 2. Documentation rule IDs do not match code implementation [HIGH]

**Files:** `site/docs/reference/rules.md`, `pkg/analyzer/rules.go`

The published documentation describes 15 rules (KC-001 through KC-015) that map to completely different detections than the code implements. For example, docs say KC-006 is "Wildcard API Groups" but code implements KC-006 as "Secrets access"; docs say KC-007 is "Privilege Escalation Chain" (multi-hop graph traversal) but code implements KC-007 as "Pod exec/attach". Users will expect functionality that does not exist. Reconcile the documentation with the actual implementation before publishing.

### 3. No apiGroup filtering in rule analysis [HIGH]

**Files:** `pkg/analyzer/analyzer.go`, `pkg/analyzer/rules.go`

The analyzer checks `resources` and `verbs` from RBAC rules but never inspects the `apiGroups` field. A CRD named `secrets` in apiGroup `custom.example.com` triggers KC-006 (false positive). Conversely, `apiGroups: ["*"]` is never detected despite the documentation claiming this is KC-006. Add apiGroup filtering to resource-based rules and add detection for wildcard apiGroups.

### 4. GitHub Action downloads binary without checksum verification [HIGH]

**File:** `.github/action.yml`, lines 35-41

The Action downloads the binary via `curl -sL` and pipes directly to `tar xz` with no SHA256 verification against the goreleaser-generated `checksums.txt`. Download the checksum file, verify the binary hash before extracting, and pin to specific versions in documentation examples rather than defaulting to `latest`.

### 5. Loader does not parse workload controllers (Deployments, DaemonSets, etc.) [MEDIUM]

**File:** `pkg/loader/loader.go`, lines 196-252

`categorize()` only parses ClusterRole, Role, ClusterRoleBinding, RoleBinding, ServiceAccount, and Pod kinds. Deployments, DaemonSets, StatefulSets, Jobs, and CronJobs are not parsed. Even if `escalationPodResources` were expanded to include these resource types, there is no workload data to analyze. This makes the tool unable to reason about privilege escalation through workload controllers, which is the most common real-world vector. Add workload controller parsing to the loader and expand the escalation detection accordingly.

### 6. Silent file processing failures in walkDir [MEDIUM]

**File:** `pkg/loader/loader.go`, line 129

`_ = processFile(path, opts, result)` discards the error. Files that exceed `MaxFileSize`, fail to read, or fail to parse produce no diagnostic output. Combined with the missing stderr warning when zero RBAC resources are found (spec requirement), users can get silently incomplete scan results. Return or collect errors, and emit warnings for skipped files to stderr.

### 7. processFile follows symlinks via os.Stat and os.ReadFile [MEDIUM]

**File:** `pkg/loader/loader.go`, lines 104-131

Inside `processFile`, `os.Stat(path)` and `os.ReadFile(path)` both follow symlinks. While the top-level `os.Lstat` check and `filepath.WalkDir`'s default symlink behavior provide mitigation, `processFile` itself does not verify the file type atomically. Use `os.Lstat` instead of `os.Stat` in `processFile`, or open with `os.Open` and use `Fstat` on the descriptor. Severity adjusted down from the security review's MEDIUM assessment because the attack preconditions (write access to scanned directory, microsecond race window) are narrow for a one-shot CLI tool, but the fix is trivial and worth doing.

### 8. Map key collision silently overwrites earlier resources [MEDIUM]

**File:** `pkg/loader/loader.go`, lines 208-251

`categorize()` stores ClusterRoles by name and Roles by `namespace/name` in maps. Duplicate definitions silently overwrite earlier entries, losing findings for the first occurrence. An attacker could place a benign duplicate role later in the directory tree to shadow a malicious one. Detect duplicate keys and emit a warning finding or analyze both definitions.

---

## Can Address Later

### 9. os.Exit(1) inside RunE bypasses deferred cleanup [MEDIUM]

**File:** `cmd/kube-chainsaw/main.go`, lines 128-133

`os.Exit(1)` is called directly inside the `RunE` handler when findings exceed the severity threshold. This bypasses deferred cleanup, breaks testability (tests must build a binary and use `exec.Command`), and is inconsistent with Cobra's error-handling contract. Return a sentinel error and handle the exit code in `main()`. Severity consensus: MEDIUM (no deferred cleanup currently exists, but the pattern will break as soon as any is added).

### 10. escalationPodResources map is incomplete [MEDIUM]

**File:** `pkg/analyzer/rules.go`, lines 53-55

The `escalationPodResources` map only contains `"pods"`. KC-012 is supposed to detect privilege escalation via workload creation, but Deployments, DaemonSets, StatefulSets, Jobs, CronJobs, and ReplicaSets are excluded. Note: this is blocked by finding 5 (loader does not parse workload controllers). Once the loader is extended, expand this map and rename to `escalationWorkloadResources`.

### 11. Exit code 2 for runtime errors is never produced [MEDIUM]

**File:** `cmd/kube-chainsaw/main.go`, lines 31-33, 59-135

The spec defines exit code 2 for "Invalid arguments or runtime error." Both argument errors and runtime errors produce exit code 1 via `os.Exit(1)`. No code path produces exit code 2. Differentiate exit codes when returning errors from `main()`.

### 12. Fingerprint does not include file path, causing cross-file collision [LOW]

**File:** `pkg/models/models.go`, lines 68-72

`ComputeFingerprint()` hashes `rule_id|resource_kind|resource_name|resource_namespace` but not the file path. Two identically named resources in different files produce the same fingerprint, and `appendIfNew` deduplicates them. Include `f.File` in the fingerprint input.

### 13. Suppression file has no size limit and no field validation [LOW]

**Files:** `pkg/suppression/suppression.go`, lines 25-37

`LoadSuppressions` calls `os.ReadFile` with no size check (unlike the manifest loader's `MaxFileSize` enforcement). It also does not validate that `rule_id` and `resource_name` are non-empty, so typos in suppressions (e.g., `KC-99` instead of `KC-009`) silently match nothing. Add a size check before reading, and validate entries after parsing.

### 14. GitHub Action argument injection surface [LOW]

**File:** `.github/action.yml`

`INPUT_FORMAT`, `INPUT_FAIL_ON`, and other inputs are interpolated directly into the command line without validation. A malicious workflow input like `--fail-on "INFO" --format "sarif" -- /etc` could override earlier arguments. While the `--` separator protects path arguments, the other inputs are placed before it and are not validated. Sanitize or validate Action inputs before interpolation.

### 15. No stderr warning when zero RBAC resources are found [LOW]

**File:** `cmd/kube-chainsaw/main.go`, lines 81-87

The spec requires a WARNING to stderr when no RBAC resources are found. The implementation silently returns exit 0 with an empty report, which can mask misconfiguration (e.g., scanning the wrong directory). Emit a warning to stderr.

### 16. Missing test fixtures for KC-005, KC-008, KC-009 [LOW]

**Files:** `testdata/dangerous/`, `pkg/analyzer/analyzer_test.go`

KC-005 (bind verb) has only a synthetic in-memory test, not a full pipeline fixture test. KC-008 (nodes access) and KC-009 (persistentvolumes access) have no tests at all. A regression removing these resources from the detection map would go undetected. Add YAML fixtures and table-driven test entries.

### 17. CGO_ENABLED not explicitly set in goreleaser config [LOW]

**Files:** `Dockerfile`, `.goreleaser.yaml`

The Dockerfile uses `FROM scratch` but the build config does not explicitly set `CGO_ENABLED=0`. Goreleaser defaults to this for cross-compilation, but an explicit setting prevents regressions. Add `CGO_ENABLED=0` to the goreleaser env block.

---

## Findings Removed (Weak Evidence)

- **SARIF output injection via resource names** (Security F10): The review asserted control character injection risk in SARIF output, then immediately acknowledged that `json.MarshalIndent` handles JSON escaping and Kubernetes name validation prevents most control characters. No concrete exploit path demonstrated.
- **--include-attack-scenarios flag missing** (Correctness F3): References an unverifiable external spec. No evidence of this flag in the repository documentation or any design document. Cannot confirm this is a real gap.

---

## Design Observations (Not Findings)

These are structural notes from the reviews that do not require action but provide context.

- **Untyped `map[string]interface{}` pervasive in models.** Every analyzer access requires type assertions with silent zero-value fallback on typos. Typed structs for PolicyRule, RoleRef, and Subjects would add compile-time safety. Worth doing when the model layer is next modified. (Architecture F-03)
- **`splitYAMLDocs` recompiles regex on every call.** Move the regex to a package-level `var` to match the pattern used by `goTemplateRe`. Minor performance improvement for large scans. (Architecture F-02)
- **Reporter interface returns `string` instead of writing to `io.Writer`.** Buffers entire reports in memory. Not a problem at current scale but limits streaming for large scans. (Architecture F-08)
- **Clean test fixtures produce findings.** Three of nine "clean" fixtures (`readonly-clusterrole.yaml`, `rolebinding-clusterrole-namespaced.yaml`, `operator-elevated-legitimate.yaml`) produce findings and are excluded from the zero-findings assertion. Either the spec's definition of "clean" or the detection logic needs adjustment. (Correctness F11, F12, F18)
- **Unbound roles defaulting to INFO severity.** Roles without bindings get INFO severity, which makes sense for deployed-state analysis but undercuts pre-deployment scanning where roles and bindings are in separate files. Interacts with finding 1 (KC-014 requiring co-located Pods). Worth revisiting the severity model for pre-deployment use cases. (Red Team observation)
