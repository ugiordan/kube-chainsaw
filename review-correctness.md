# kube-chainsaw Correctness Review

Review date: 2026-05-29
Reviewer focus: Spec compliance, detection rule correctness, severity logic, fingerprint computation, suppression matching, CLI flags, output behavior, exit codes, edge cases.

---

## Finding 1: KC-014 detection only fires for Pods, not for standalone RoleBinding-to-ClusterRole patterns

**Severity: HIGH**
**Files:** `pkg/analyzer/analyzer.go` lines 196-215

The spec says KC-014 should detect "RoleBinding grants cluster-wide permissions via ClusterRole". However, the implementation in `analyzePrivilegeChains()` only fires KC-014 when a **Pod** exists that uses an SA referenced by a RoleBinding pointing to a ClusterRole. If there is a RoleBinding referencing a ClusterRole but no Pod using the SA in the same manifest set, KC-014 never fires.

This is architecturally wrong. The KC-014 check should iterate over all RoleBindings that reference ClusterRoles, regardless of whether a Pod exists in the scan. Many real-world scenarios have RoleBindings deployed separately from Pods.

The `rolebinding-to-clusterrole.yaml` test fixture works only because it conveniently includes a Pod. The `rolebinding-clusterrole-namespaced.yaml` clean fixture also includes a Pod and relies on KC-014 firing. But any RoleBinding-to-ClusterRole without a co-located Pod would be silently missed.

**Impact:** False negatives. A large class of real-world RoleBinding-to-ClusterRole misconfigurations will be undetected if the Pod definition is in a separate file/repo.

---

## Finding 2: KC-013 only detects cluster-admin, not arbitrary dangerous ClusterRoles

**Severity: MEDIUM**
**Files:** `pkg/analyzer/analyzer.go` lines 184-193

KC-013 (Pod with cluster-admin access) hardcodes the check to `roleRefName == "cluster-admin"`. While the spec also says "cluster-admin binding detection", the broader privilege chain analysis described in the spec (SA -> ClusterRoleBinding -> ClusterRole mapping, Pod -> SA -> Role chains identifying pods with excessive permissions) is only partially implemented. Pods bound to other extremely dangerous ClusterRoles (e.g., a custom ClusterRole with `*/*` permissions) won't trigger KC-013.

This is technically spec-compliant for KC-013 specifically, but the privilege chain analysis described in the spec's "Privilege Chain Analysis" section is incomplete. The spec says "Pod -> SA -> Role chains (identifying pods with excessive permissions)" which implies more than just cluster-admin matching.

---

## Finding 3: `--include-attack-scenarios` flag is missing from CLI

**Severity: MEDIUM**
**Files:** `cmd/kube-chainsaw/main.go`

The spec defines `--include-attack-scenarios` as a CLI flag (see Arguments table) and the `plugins.py` module for plugin loading. Neither the flag nor any plugin loading mechanism exists in the Go implementation. The `Finding` struct in `models.go` also omits the `attack_scenarios` field present in the spec's Python dataclass.

This is a spec gap in the implementation. While the paid addon may not be ready, the flag should at least be defined and handled with the appropriate warning message when the addon is not installed, per the spec.

---

## Finding 4: No stderr warning when zero RBAC resources are found

**Severity: LOW**
**Files:** `cmd/kube-chainsaw/main.go` lines 81-87

The spec says: "If `load_paths()` finds zero RBAC resources, `analyze()` returns empty list and emits WARNING to stderr: 'No RBAC resources found in scanned paths'". The implementation in `main.go` calls `analyzer.Analyze(resources)` which returns nil for empty resources, but no stderr warning is emitted. The scan silently succeeds with exit 0, which could mask misconfiguration (e.g., scanning the wrong directory).

---

## Finding 5: Exit code 2 for runtime errors is not reliably produced

**Severity: MEDIUM**
**Files:** `cmd/kube-chainsaw/main.go` lines 31-33, 59-135

The spec defines exit code 2 for "Invalid arguments or runtime error". The `main()` function calls `os.Exit(1)` when `rootCmd.Execute()` returns an error (line 32-33). Cobra returns errors for both invalid arguments and runtime errors from `RunE`. This means runtime errors (failed manifest loading, unwritable output file) produce exit code 1, not exit code 2 as specified.

Additionally, the exit code 1 logic on line 129 uses `os.Exit(1)` directly from within `RunE`, which means Cobra's deferred cleanup never runs. If `RunE` returns an error, `main()` also calls `os.Exit(1)`. There is no path that produces exit code 2.

---

## Finding 6: `computeSeverity` does not distinguish "namespace-scoped with group subjects only" vs other subjects

**Severity: LOW**
**Files:** `pkg/analyzer/rules.go` lines 103-124

The spec's severity table includes two rows for namespace-scoped ClusterRoles:
- "Namespace-scoped ClusterRole, group subjects only" -> WARNING
- "Namespace-scoped ClusterRole, other subjects" -> WARNING

Both map to WARNING in the spec, so the implementation's simplified logic (just checking `scope.NamespaceScoped` without examining subject types) produces correct severity values. However, the `SubjectTypes` field is populated in `BindingScope` but never read during severity computation. This is dead code that should either be used (for future differentiation) or documented as intentionally unused.

---

## Finding 7: Severity for KC-003/KC-004/KC-005 on dangerous verbs includes wildcard check from the same rule, which may inflate severity

**Severity: MEDIUM**
**Files:** `pkg/analyzer/analyzer.go` lines 53-69

In `checkRules()`, the `hasWildcards` variable is computed per-rule (per YAML rule block), checking if the same rule block has `verbs: ["*"]` or `resources: ["*"]`. This is passed to `computeSeverity()`.

Consider a ClusterRole with:
```yaml
rules:
- resources: ["clusterroles"]
  verbs: ["escalate"]
```

Here `hasWildcardVerb` is false and `hasWildcardResource` is false, so `hasWildcards` is false. This is correct.

But consider:
```yaml
rules:
- resources: ["*"]
  verbs: ["escalate"]
```

Here `hasWildcards` is true (because resources includes `*`), so the escalate verb finding (KC-003) gets CRITICAL severity if cluster-wide. This is also correct per the spec, since the presence of wildcards in the same rule is a meaningful severity signal.

The logic correctly scopes wildcards to the individual rule block, not the entire ClusterRole. This is actually reasonable behavior. No bug here on closer inspection.

---

## Finding 8: `sigs.k8s.io/yaml` uses `yaml.Unmarshal` which delegates to `go-yaml`, not Python's `yaml.safe_load`

**Severity: INFO**
**Files:** `pkg/loader/loader.go` line 172, `go.mod`

The spec is written for Python and mandates `yaml.safe_load()` / `yaml.safe_load_all()`. The Go implementation uses `sigs.k8s.io/yaml` which under the hood uses `go-yaml/yaml` (v2). Go's yaml library does not support arbitrary code execution from YAML tags the way Python's `yaml.load()` does, so the security concern is inherently mitigated by the language choice. This is correct behavior for a Go port.

However, the spec-mandated `test_security.py` tests for `!!python/object` rejection don't have Go equivalents. There is no `test_security_test.go`. While Go's yaml library won't execute Python objects, having explicit tests that document the security posture would match the spec's intent.

---

## Finding 9: KC-005 (bind verb) has no dedicated fixture

**Severity: LOW**
**Files:** `testdata/dangerous/`

The spec lists KC-005 as "Dangerous verb: bind" and the rule table test in `analyzer_test.go` tests KC-003 (escalate) and KC-004 (impersonate) with dedicated fixtures, but there is no `bind-verb.yaml` fixture. KC-005 is only tested via the synthetic `TestBindVerb` test that constructs resources in-memory. While this works, it doesn't validate the full pipeline (loader -> analyzer) for the bind verb detection path.

---

## Finding 10: KC-008 (nodes) and KC-009 (persistentvolumes) have no dedicated fixtures or tests

**Severity: MEDIUM**
**Files:** `testdata/dangerous/`, `pkg/analyzer/analyzer_test.go`

The spec defines 15 rules (KC-001 through KC-015). The `TestRuleDetection` table-driven test covers KC-001, KC-002, KC-003, KC-004, KC-006, KC-007, KC-010, KC-011, KC-012, KC-013, KC-014, KC-015. Missing from the table:

- **KC-005** (bind verb): tested separately via `TestBindVerb` with synthetic data
- **KC-008** (nodes access): no test at all, no fixture
- **KC-009** (persistentvolumes access): no test at all, no fixture

These rules exist in the `dangerousResources` map in `rules.go`, so they would fire if the right resources appeared. But without any test coverage, a regression removing "nodes" or "persistentvolumes" from the map would go undetected.

---

## Finding 11: `operator-elevated-legitimate.yaml` creates a false-positive-clean test that actually produces findings

**Severity: MEDIUM**
**Files:** `testdata/clean/operator-elevated-legitimate.yaml`, `pkg/analyzer/analyzer_test.go` lines 374-387

The `operator-elevated-legitimate.yaml` fixture is listed as a "clean" fixture in the spec, but the test `TestOperatorElevatedLegitimate` does not assert zero findings. Instead, it asserts findings are below HIGH severity, explicitly excluding KC-014. This means the "clean" fixture actually produces KC-012 (escalation via pod creation from `create` on deployments/statefulsets) and KC-014 findings.

Wait, let me re-examine. The `escalationPodResources` map only contains "pods", not "deployments" or "statefulsets". So KC-012 should not fire. But the CLI test `TestCLI_Suppressions` suppresses KC-012 for `operator-elevated-legitimate-role` and KC-014 for `operator-elevated-legitimate-binding`, which means these findings ARE being produced during a clean/ directory scan, contradicting the "clean fixture = no findings" intent.

The issue is that `operator-elevated-legitimate.yaml` uses a RoleBinding referencing a ClusterRole, which triggers KC-014. The CLI suppression test confirms this. The `TestCleanFixturesProduceNoFindings` test explicitly excludes this fixture from its assertion list. This is not really "clean" in the spec's sense; it's more of a "legitimate but flagged" fixture. The spec says these should have "no findings (false positive validation)" but the implementation accepts that some informational findings are expected.

The CLI suppression test also suppresses KC-012 for this fixture, but I cannot see how KC-012 fires since `escalationPodResources` only contains "pods" and the fixture uses "deployments" and "statefulsets". Either the suppression is unnecessary (dead suppression entry) or there's a bug I'm not seeing in how escalation combo interacts with wildcard handling.

---

## Finding 12: `clean/rolebinding-clusterrole-namespaced.yaml` is listed as clean but triggers KC-014

**Severity: LOW**
**Files:** `testdata/clean/rolebinding-clusterrole-namespaced.yaml`, `pkg/analyzer/analyzer_test.go` lines 154-183

This fixture is a RoleBinding referencing a ClusterRole at namespace scope, which the spec says is a "legitimate pattern". However, since the fixture includes a Pod, KC-014 will fire (RoleBinding referencing ClusterRole). The `TestCleanFixturesProduceNoFindings` test does not include this fixture (it's excluded from `cleanFiles` list), and the CLI suppression test suppresses KC-014 for this binding name.

This confirms that "clean" fixtures are not truly clean. The spec says this fixture should produce "no findings" but it does produce KC-014.

---

## Finding 13: Fingerprint does not include the `file` field, allowing cross-file collisions

**Severity: LOW**
**Files:** `pkg/models/models.go` lines 68-72

The spec defines fingerprint as `SHA256 of (rule_id + "|" + resource_kind + "|" + resource_name + "|" + (resource_namespace or ""))`. The implementation matches this exactly. However, this means two identically named resources in different files produce the same fingerprint, and `appendIfNew` in `analyzer.go` (line 295-302) will deduplicate them. If two different YAML files define a `ClusterRole` named `admin` with different rules, only one finding per rule ID will be kept. This is a design choice that matches the spec, but it could cause silent loss of findings in repos with name collisions across files.

---

## Finding 14: `os.Exit(1)` inside `RunE` bypasses Cobra's error handling

**Severity: MEDIUM**
**Files:** `cmd/kube-chainsaw/main.go` lines 128-131

When findings meet the severity threshold, the code calls `os.Exit(1)` directly inside `RunE`. This bypasses any deferred cleanup and prevents Cobra from running post-run hooks. More critically, it means the function never returns an error to Cobra, so the error flow is inconsistent: some errors return `error` (handled by `main()`) while the threshold exit is a direct `os.Exit`.

A cleaner approach would be to return a sentinel error that `main()` checks, or set a flag and check after `Execute()` returns. The current approach works but makes testing harder and deferred calls unreliable.

---

## Finding 15: `--quiet` with `--output` writes file but returns exit 0 even when RunE returns nil

**Severity: INFO**
**Files:** `cmd/kube-chainsaw/main.go` lines 99-134

The dual output behavior is correctly implemented. When `--quiet` is set, stdout is suppressed. When `--output` is set, the file is written. The exit code logic on lines 128-131 still runs regardless of `--quiet`. This matches the spec.

However, there is no test that verifies `--quiet` still produces correct exit code 1 when dangerous findings exist. The `TestCLI_Quiet` test only runs against `clean/` fixtures (exit 0). Adding a test with `--quiet` on `dangerous/` fixtures would verify exit code 1 still fires in quiet mode.

---

## Finding 16: Loader uses `sigs.k8s.io/yaml.Unmarshal` for individual docs instead of the standard `yaml.safe_load_all` equivalent

**Severity: INFO**
**Files:** `pkg/loader/loader.go` lines 159-184

The loader manually splits YAML documents on `---` separators using a regex, then unmarshals each document individually. The spec calls for `yaml.safe_load_all()` which handles multi-document YAML natively. The manual splitting approach has a known limitation with `---` inside quoted strings or block scalars, which could cause incorrect document boundaries. The regex `(?m)^---\s*$` mitigates most cases but isn't perfect.

For Kubernetes manifests this is fine in practice, since `---` inside values is extremely rare. The implementation matches the spec's intent if not its exact mechanism.

---

## Finding 17: KC-011 escalation combo with wildcard verb "*" + roles resources triggers both KC-002 and KC-011

**Severity: INFO**
**Files:** `pkg/analyzer/analyzer.go` lines 56-119

When a rule block has `verbs: ["*"]` and `resources: ["roles"]`, the code will:
1. Fire KC-002 (wildcard verb) via the dangerous verbs check
2. Fire KC-011 (escalation binding combo) because `hasEscalationBindingCombo` returns true (`"*"` matches `escalationMutationVerbs` check at analyzer.go line 130)

This is correct behavior per the spec: "A single ClusterRole with both wildcard verbs and secrets access generates two findings (KC-002 and KC-006), not one consolidated finding." The same logic applies to wildcard verbs and escalation combos. Multiple findings per resource is the intended design.

---

## Finding 18: `TestCleanFixturesProduceNoFindings` omits 3 of 9 clean fixtures

**Severity: MEDIUM**
**Files:** `pkg/analyzer/analyzer_test.go` lines 154-183

The spec lists 9 clean fixtures. The `TestCleanFixturesProduceNoFindings` test only checks 6:
- `create-configmaps.yaml`
- `explicit-namespace.yaml`
- `go-templates.yaml`
- `minimal-role.yaml`
- `multi-doc-mixed.yaml`
- `sa-no-bindings.yaml`

Missing from the clean-no-findings assertion:
- `readonly-clusterrole.yaml` (tested separately in `TestReadonlyClusterRoleNoFindings` but with weaker assertions)
- `rolebinding-clusterrole-namespaced.yaml` (produces KC-014, so excluded)
- `operator-elevated-legitimate.yaml` (produces KC-012/KC-014, tested separately)

The 3 missing fixtures all produce findings, which contradicts the spec's intent that clean fixtures should have "no findings (false positive validation)". Either the spec is wrong about these being false-positive-free, or the detection logic is too aggressive.

---

## Finding 19: No `--no-default-excludes` test coverage

**Severity: LOW**
**Files:** `cmd/kube-chainsaw/main_test.go`, `pkg/loader/loader_test.go`

The `--no-default-excludes` flag is defined in the CLI but has no integration test. There's a unit test for default excludes (`TestDefaultExcludes`) but no test verifies that passing `--no-default-excludes` actually includes `.git` and `vendor` directories in the scan. A regression that breaks this flag would go undetected.

---

## Finding 20: `readonly-clusterrole.yaml` is bound cluster-wide but the test only asserts absence of specific rules

**Severity: LOW**
**Files:** `pkg/analyzer/analyzer_test.go` lines 186-197, `testdata/clean/readonly-clusterrole.yaml`

The `readonly-clusterrole.yaml` fixture binds a ClusterRole with `get/list/watch` on `pods/services/namespaces` to `system:authenticated` Group via ClusterRoleBinding. The test asserts it doesn't trigger KC-001, KC-002, or KC-006, but doesn't assert zero total findings. Since pods, services, and namespaces are not in the `dangerousResources` map, no findings should fire. The test should `assert.Empty(t, findings)` for completeness.

---

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| HIGH | 1 | KC-014 only fires when Pod exists, missing standalone RoleBinding-to-ClusterRole detection |
| MEDIUM | 6 | Missing exit code 2, missing CLI flag, missing test fixtures for KC-008/KC-009, clean fixtures produce findings, os.Exit inside RunE |
| LOW | 5 | No stderr warning for empty resources, dead subject-type code, missing bind verb fixture, missing --no-default-excludes test, weak readonly test assertion |
| INFO | 4 | No security tests for Go, manual YAML splitting, expected multi-finding behavior, dual output behavior correct |
