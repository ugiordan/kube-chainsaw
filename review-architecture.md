# kube-chainsaw Architecture and Code Quality Review

Review date: 2026-05-29

---

## Overall Assessment

This is a well-structured, focused Go CLI tool for Kubernetes RBAC security analysis. The package boundaries are clean, the data flow is linear and easy to follow (loader -> analyzer -> reporter), and the test coverage is solid. The dependency footprint is minimal. The codebase reflects someone who knows Go idioms well. That said, there are concrete issues worth fixing, ranging from a real bug in the CLI to design choices that will cause friction as the tool grows.

---

## Findings

### F-01: os.Exit(1) inside RunE breaks testability and skips deferred cleanup

**Severity: HIGH**  
**File:** `cmd/kube-chainsaw/main.go`, lines 128-133

The `run` function is used as a `cobra.Command.RunE` handler, which means cobra expects it to return an error for non-zero exit. Instead, the function calls `os.Exit(1)` directly when a finding exceeds the severity threshold:

```go
for _, f := range findings {
    if !f.Suppressed && f.Severity >= failSeverity {
        os.Exit(1)
    }
}
```

This has multiple problems:
- Any deferred functions in the call stack are skipped (not currently an issue, but will be as soon as someone adds cleanup logic).
- The function returns `nil` on the success path, which means cobra sees no error and prints nothing. But it calls `os.Exit(1)` for failure, which means cobra never gets to handle the error either. The error handling contract with cobra is inconsistent.
- It makes integration testing harder. The CLI tests work around this by building a binary and checking exit codes via `exec.Command`, but unit-testing the `run` function directly is impossible because `os.Exit` kills the test process.

**Recommendation:** Return a sentinel error (e.g., `var ErrFindingsExceedThreshold = errors.New("findings exceed severity threshold")`) and handle the exit code in `main()` or via cobra's `PersistentPostRunE`. This keeps `run` pure and testable.

---

### F-02: splitYAMLDocs compiles a regex on every call

**Severity: MEDIUM**  
**File:** `pkg/loader/loader.go`, line 193

```go
func splitYAMLDocs(content string) []string {
    re := regexp.MustCompile(`(?m)^---\s*$`)
    return re.Split(content, -1)
}
```

`regexp.MustCompile` is called inside the function body, so a new regex is compiled for every file processed. Given that `goTemplateRe` at line 29 is already correctly compiled at package init time, this is an inconsistency. For a scan of hundreds of manifests, this adds measurable overhead.

**Recommendation:** Move the regex to a package-level `var`, matching the pattern already used for `goTemplateRe`.

---

### F-03: Untyped map[string]interface{} used pervasively instead of typed structs

**Severity: MEDIUM**  
**File:** `pkg/models/models.go`, `pkg/loader/loader.go`, `pkg/analyzer/analyzer.go`

The `ClusterRoleData.Rules`, `BindingData.RoleRef`, `BindingData.Subjects`, and all the `Doc` fields use `map[string]interface{}`. This means:
- Every access in the analyzer requires type assertions with fallback handling (e.g., `roleRef["name"].(string)`)
- There is no compile-time safety. A typo in a map key (e.g., `"names"` instead of `"name"`) silently returns a zero value.
- The `Doc` field on every data struct stores the entire raw document but is only used in `isAggregated(cr.Doc)` to check for the `aggregationRule` key. It is carried around for no other purpose.

**Recommendation:**
- Define typed structs for RBAC rule entries (`PolicyRule`), role references, and subjects. The Kubernetes API types are well-defined. You do not need to import `k8s.io/api` for this. Just define the subset you need.
- If `Doc` is only used for the aggregation check, replace it with a boolean `IsAggregated` field on `ClusterRoleData` and drop the raw document storage entirely. This reduces memory pressure on large scans.

---

### F-04: Fingerprint does not include the File path, causing cross-file collision

**Severity: MEDIUM**  
**File:** `pkg/models/models.go`, lines 68-72

```go
func (f *Finding) ComputeFingerprint() {
    data := fmt.Sprintf("%s|%s|%s|%s", f.RuleID, f.ResourceKind, f.ResourceName, f.ResourceNamespace)
    hash := sha256.Sum256([]byte(data))
    f.Fingerprint = fmt.Sprintf("%x", hash)
}
```

If two different files define a ClusterRole with the same name (e.g., during a multi-repo scan, or in overlapping Helm charts), the fingerprint will be identical and `appendIfNew` will deduplicate them as if they were the same finding. This is incorrect. The file path is a meaningful distinguishing attribute.

**Recommendation:** Include `f.File` in the fingerprint hash input. This makes fingerprints unique per file-resource-rule combination.

---

### F-05: appendIfNew is O(n^2)

**Severity: LOW**  
**File:** `pkg/analyzer/analyzer.go`, lines 295-302

```go
func appendIfNew(findings []models.Finding, f models.Finding) []models.Finding {
    for _, existing := range findings {
        if existing.Fingerprint == f.Fingerprint {
            return findings
        }
    }
    return append(findings, f)
}
```

This linear scan runs for every finding being appended. In the privilege chain analysis phase, this is called inside nested loops over pods, bindings, and roles. For large clusters with many pods and bindings, this is O(pods * bindings * findings). In practice this is likely fine for now (RBAC manifests are usually small), but it is worth noting.

**Recommendation:** Use a `map[string]bool` (keyed by fingerprint) alongside the findings slice for O(1) dedup. The `checkRules` function already does this correctly with its `seen` map.

---

### F-06: escalationPodResources is incomplete

**Severity: MEDIUM**  
**File:** `pkg/analyzer/rules.go`, lines 53-55

```go
var escalationPodResources = map[string]bool{
    "pods": true,
}
```

The KC-012 rule is supposed to detect privilege escalation via workload creation, but the resource list only includes `pods`. Creating a Deployment, DaemonSet, StatefulSet, Job, or CronJob with a privileged ServiceAccount is an equally valid (and more common) escalation vector. The rule description says "pod creation" but the remediation text says "Restrict pod creation to CI/CD pipelines and use PodSecurityPolicies", which implies workload controllers should be included.

**Recommendation:** Add `"deployments"`, `"daemonsets"`, `"statefulsets"`, `"jobs"`, `"cronjobs"`, and `"replicasets"` to `escalationPodResources`. Rename the variable to `escalationWorkloadResources` to match the broader scope.

---

### F-07: No validation of suppression file contents

**Severity: LOW**  
**File:** `pkg/suppression/suppression.go`, lines 25-37

`LoadSuppressions` parses the YAML but performs no validation on the entries. A suppression with an empty `rule_id` or `resource_name` will silently never match anything. A suppression with a typo in `rule_id` (e.g., `"KC-99"`) will also silently do nothing.

**Recommendation:** Validate each suppression entry after parsing. At minimum, check that `rule_id` is non-empty and matches a known rule pattern (or better, exists in the `ruleDescriptions` map). Warn or error on empty `resource_name`.

---

### F-08: Reporter interface returns string instead of writing to io.Writer

**Severity: LOW**  
**File:** `pkg/reporter/reporter.go`

```go
type Reporter interface {
    Render(findings []models.Finding) (string, error)
}
```

Returning a full string means the entire report is buffered in memory before being written to stdout or a file. For the console reporter, this also means string building via `strings.Builder` followed by `fmt.Print(rendered)`, which is a double copy. For large reports (thousands of findings across a big cluster), this is wasteful.

**Recommendation:** Consider `Render(findings []models.Finding, w io.Writer) error` as the interface signature. This enables streaming output and avoids the intermediate string allocation. The console reporter can write directly to `os.Stdout`, and the file reporter can write directly to the file handle.

---

### F-09: JSON reporter produces nil array when findings list is nil

**Severity: LOW**  
**File:** `pkg/reporter/json.go`, line 30

When `findings` is nil (e.g., empty scan), `make([]jsonFinding, len(findings))` creates a zero-length slice, which serializes to `[]` in JSON. This is correct. However, if `Render(nil)` is called, the `Findings` field is `make([]jsonFinding, 0)`, which produces:

```json
{"findings": []}
```

This is fine. But the test `TestJSONReporter_EmptyFindings` passes `nil` and asserts `Len(parsed.Findings, 0)`. The behavior is consistent, but worth noting that `make([]jsonFinding, len(nil))` is equivalent to `make([]jsonFinding, 0)`. No action needed, but the test comment could be clearer about what is being tested.

---

### F-10: SARIF reporter does not differentiate between CRITICAL and HIGH

**Severity: LOW**  
**File:** `pkg/reporter/sarif.go`, lines 89-100

```go
func severityToSARIFLevel(s models.Severity) string {
    switch s {
    case models.SeverityCritical, models.SeverityHigh:
        return "error"
    ...
    }
}
```

Both CRITICAL and HIGH map to `"error"`. While SARIF 2.1.0 only has `error`, `warning`, and `note` levels, the spec also supports `properties` bags and `rank` (0.0-100.0) for finer granularity. Consumers like GitHub Code Scanning and SARIF viewers use these to sort results.

**Recommendation:** Add a `rank` property to distinguish CRITICAL (rank 90+) from HIGH (rank 70+). This preserves the severity distinction in SARIF-consuming tools without violating the spec.

---

### F-11: Missing KC-005 (bind verb) and KC-008/KC-009 fixture tests

**Severity: LOW**  
**File:** `pkg/analyzer/analyzer_test.go`

The table-driven `TestRuleDetection` does not include entries for:
- KC-005 (bind verb). There is a separate `TestBindVerb` test that builds resources programmatically, but there is no YAML fixture under `testdata/dangerous/` for it.
- KC-008 (nodes access). No fixture or test.
- KC-009 (PV access). No fixture or test.

These rules exist in the detection logic (`dangerousResources` map) and could regress undetected.

**Recommendation:** Add fixture YAML files for `bind-verb.yaml`, `nodes-access.yaml`, and `pv-access.yaml` under `testdata/dangerous/` and add entries to the `TestRuleDetection` table.

---

### F-12: testdataDir() helper is duplicated across test packages

**Severity: LOW**  
**Files:** `pkg/loader/loader_test.go` line 13, `pkg/analyzer/analyzer_test.go` line 13

Both packages define an identical `testdataDir()` function:

```go
func testdataDir() string {
    dir, _ := filepath.Abs("../../testdata")
    return dir
}
```

This is minor, but if the testdata location ever changes, both must be updated.

**Recommendation:** Either accept the duplication (it is small) or add a `internal/testutil` package with a shared helper. Given the size of this codebase, the duplication is acceptable, but worth noting.

---

### F-13: CLI integration tests rebuild the binary for every test function

**Severity: LOW**  
**File:** `cmd/kube-chainsaw/main_test.go`, lines 17-24

Each test function calls `testBinary(t)`, which runs `go build` to produce a fresh binary. With 12 test functions in this file, that is 12 separate compilations. Go's build cache helps, but it is still unnecessary I/O.

**Recommendation:** Use `TestMain(m *testing.M)` to build the binary once into a package-level variable and reuse it across all tests. Example:

```go
var testBin string

func TestMain(m *testing.M) {
    // build once
    dir, _ := os.MkdirTemp("", "kube-chainsaw-test")
    testBin = filepath.Join(dir, "kube-chainsaw")
    cmd := exec.Command("go", "build", "-o", testBin, ".")
    if out, err := cmd.CombinedOutput(); err != nil {
        fmt.Fprintf(os.Stderr, "build failed: %s\n%s", err, out)
        os.Exit(1)
    }
    os.Exit(m.Run())
}
```

---

### F-14: Symlink detection at the top level uses os.Lstat but filepath.WalkDir also resolves symlinks differently

**Severity: LOW**  
**File:** `pkg/loader/loader.go`, lines 65-73, 109-114

At the top level, `os.Lstat` is used to detect symlinks and skip them. Inside `walkDir`, the code checks `d.Type()&fs.ModeSymlink != 0`. However, `filepath.WalkDir` does not follow symlinks by default, so the symlink check inside `walkDir` for regular files (line 113-114) will never trigger for symlink files because `WalkDir` does not visit them. The check for symlink directories (line 111-112) is similarly redundant.

The top-level `os.Lstat` check is correct and necessary. The internal walkDir checks are harmless but dead code.

**Recommendation:** Add a comment explaining the symlink safety contract, or remove the dead code inside walkDir's symlink checks.

---

### F-15: No apiGroup filtering in rule analysis

**Severity: MEDIUM**  
**File:** `pkg/analyzer/analyzer.go`, `pkg/analyzer/rules.go`

The analyzer checks `resources` and `verbs` from RBAC rules but never checks `apiGroups`. This means a rule granting access to a custom resource named `"secrets"` in apiGroup `"custom.example.com"` would be flagged as KC-006 (Secrets access), even though it has nothing to do with core Kubernetes secrets (`apiGroups: [""]`).

Similarly, `"nodes"` in a custom apiGroup would trigger KC-008.

This can produce false positives in environments with CRDs that happen to share names with core resources.

**Recommendation:** For resource-based rules (KC-006, KC-007, KC-008, KC-009, KC-010), also check that `apiGroups` includes `""` (core) or `"rbac.authorization.k8s.io"` as appropriate. At minimum, do not flag resources that explicitly exclude the relevant apiGroup.

---

### F-16: Dependency on PodSecurityPolicies in remediation text (deprecated API)

**Severity: LOW**  
**File:** `pkg/analyzer/rules.go`, line 96

```go
RuleEscalationPodCreation: "Restrict pod creation to CI/CD pipelines and use PodSecurityPolicies",
```

PodSecurityPolicy was removed in Kubernetes 1.25 (released August 2022). The remediation should reference Pod Security Admission (PSA) / Pod Security Standards instead.

**Recommendation:** Update to: `"Restrict pod creation to CI/CD pipelines and enforce Pod Security Standards via Pod Security Admission"`.

---

## Positive Observations

Things done well that are worth calling out:

- **Clean package boundaries.** The loader, analyzer, reporter, and suppression packages have no circular dependencies and minimal coupling. The data flows through `models.LoadedResources` and `models.Finding` as clean contracts.
- **Table-driven tests** are used consistently across all packages. Edge cases (nil inputs, empty inputs, malformed files) are covered.
- **Severity computation** is contextual (based on binding scope and wildcards), not just hardcoded per rule. This is a genuinely useful design that avoids the "everything is CRITICAL" problem common in security tools.
- **Go template preprocessing** is a pragmatic solution for scanning Helm charts without pulling in a full template engine.
- **Minimal dependencies.** Only cobra, go-sarif, testify, and sigs.k8s.io/yaml. No kitchen-sink frameworks.
- **SARIF output** with fingerprints and suppressions makes this tool CI-pipeline-ready out of the box.

---

## Summary by Severity

| Severity | Count | Finding IDs |
|----------|-------|-------------|
| HIGH     | 1     | F-01 |
| MEDIUM   | 4     | F-03, F-04, F-06, F-15 |
| LOW      | 8     | F-02, F-05, F-07, F-08, F-09, F-10, F-11, F-12, F-13, F-14, F-16 |

Total: 16 findings. No blockers. F-01 (os.Exit in RunE) and F-06 (incomplete workload resources) are the most impactful to fix first.
