# Red Team Audit of kube-chainsaw Reviews

Auditor: red team agent
Date: 2026-05-29
Scope: Cross-review of security, architecture, and correctness reviews against actual source code.

---

## 1. Severity Inflation

### FLAG: SECURITY-F2 (Symlink TOCTOU race) - MEDIUM is inflated

The security review rates a symlink TOCTOU race at MEDIUM. This requires an attacker with write access to the directory being scanned, in a race window measured in microseconds, on a tool that runs as a one-shot CLI. The attack preconditions are unrealistic for a static analysis tool invoked by the user on their own files (or in CI on a freshly checked-out repo). The architecture review (F-14) correctly calls this out as dead code in walkDir rather than an exploitable vulnerability. Should be LOW at most.

### FLAG: SECURITY-F6 (YAML bomb / alias expansion) - MEDIUM is inflated

The claim that `sigs.k8s.io/yaml` is vulnerable to YAML bombs is speculative. The review says "after alias expansion, the in-memory representation could be much larger" but provides no evidence of actual expansion behavior in the Go yaml library. `go-yaml` v2 (which `sigs.k8s.io/yaml` wraps) does not do unbounded alias expansion the way Python's PyYAML does. Combined with the 10MB file size cap, this is theoretical. The review itself acknowledges "The 10MB file size cap provides some mitigation." Should be LOW/INFO.

### FLAG: ARCHITECTURE-F01 (os.Exit in RunE) - HIGH is inflated

The architecture review rates this HIGH. It is a real code quality issue (breaks testability, skips deferred cleanup). But there is currently no deferred cleanup to skip, and the integration tests work around it. For a v0.1.0 CLI tool, this is a MEDIUM quality improvement, not a HIGH severity finding. The security review correctly rates the same issue as LOW.

---

## 2. Severity Deflation

### FLAG: CORRECTNESS-F1 (KC-014 only fires with co-located Pod) - HIGH is correct, possibly under-discussed

This is the most impactful real bug across all three reviews and only the correctness review caught it. The `analyzePrivilegeChains()` function at `analyzer.go:170-215` iterates over `resources.Pods` and only emits KC-014 when a Pod exists that uses the SA referenced by the RoleBinding. If the Pod definition is in a separate file (extremely common in real deployments), KC-014 never fires. This is an actual false negative in the core detection logic. Both the security and architecture reviews missed this entirely.

### FLAG: ARCHITECTURE-F15 (No apiGroup filtering) - MEDIUM is deflated, should be HIGH

The analyzer completely ignores the `apiGroups` field in RBAC rules. This means any CRD with a resource named `secrets`, `nodes`, or `persistentvolumes` in a custom API group will trigger false positives. More critically, the documentation at `site/docs/reference/rules.md` describes KC-006 as "Wildcard API Groups" detection (detecting `apiGroups: ["*"]`), but the code implements KC-006 as "Secrets access" detection. The docs and code disagree on what half the rule IDs mean. This is a significant detection gap for a security tool and also a spec/implementation mismatch that none of the reviewers fully traced.

---

## 3. Groupthink / Shared Assumptions

### FLAG: All three reviews assume the rule IDs in code match the spec

The correctness review references a "spec" and claims the implementation matches it for some rules. The architecture review references rule descriptions. The security review takes the code's rule definitions at face value. None of them checked whether the documentation (`site/docs/reference/rules.md`) matches the code. It does not.

The docs define:
- KC-003 = "Cluster-Admin Binding"
- KC-004 = "Default ServiceAccount with Elevated Permissions"
- KC-005 = "System ServiceAccount Binding"
- KC-006 = "Wildcard API Groups"
- KC-007 = "Privilege Escalation Chain" (multi-hop graph traversal)
- KC-008 = "ServiceAccount Token Escalation"
- KC-009 = "Unbound Role"

The code implements:
- KC-003 = Escalate verb
- KC-004 = Impersonate verb
- KC-005 = Bind verb
- KC-006 = Secrets access
- KC-007 = Pod exec/attach
- KC-008 = Nodes access
- KC-009 = PersistentVolume access

These are completely different detection rules. The documentation describes a substantially more advanced tool than what the code actually implements. This is either a planned-vs-implemented gap or the docs were written for a different version of the tool.

### FLAG: All three reviews accept the severity model without questioning the "unbound = INFO" assumption

The `computeSeverity` function at `rules.go:103-124` assigns INFO severity to findings on unbound roles (roles with no binding). All three reviews accept this without question. However, unbound roles are often a pre-deployment scan scenario (manifests in a repo that will be applied together). Treating unbound roles as INFO means a scan of a ClusterRole manifest file without its corresponding ClusterRoleBinding (stored in a different file or different directory) will produce only INFO findings, effectively suppressing all alerts. This interacts badly with KC-014 bug above: the tool silently downgrades severity when resources are split across files, which is the default in real repositories.

---

## 4. Weak Evidence

### FLAG: SECURITY-F10 (SARIF output injection) - asserted without proof

The security review claims "malicious manifest with crafted metadata.name values containing control characters" could cause issues in SARIF viewers, then immediately contradicts itself: "The `json.MarshalIndent` call handles JSON escaping, so JSON injection is not possible." The finding then pivots to hypothetical SARIF viewer behavior without evidence. This is speculation, not a finding. The Kubernetes name regex already prevents most control characters in real manifests.

### FLAG: CORRECTNESS-F3 (--include-attack-scenarios flag missing) - references a "spec" that is never cited

The correctness review references a spec defining `--include-attack-scenarios` and a `plugins.py` module. No such spec file exists in the repository. If this is from an external design document, the finding is valid but the evidence is unverifiable. If the "spec" is the documentation site, the docs don't mention this flag either.

---

## 5. Contradictions Between Reviewers

### FLAG: os.Exit severity disagreement

- Security review (Finding 3): LOW
- Architecture review (F-01): HIGH
- Correctness review (Finding 14): MEDIUM

Three different severities for the same issue. The security review's LOW is closest to correct for a v0.1.0 release. The architecture review's HIGH only holds if you weight testability and future-proofing heavily, which is reasonable for a code quality review but not for a release-blocking assessment.

### FLAG: Symlink handling assessment contradicts

- Security review (Finding 2): Calls it a TOCTOU race, rates MEDIUM, recommends using `os.Open` + `Fstat`.
- Architecture review (F-14): Calls the symlink checks inside walkDir "dead code" since `filepath.WalkDir` does not follow symlinks by default. Rates LOW.

The architecture review's analysis is more accurate. `filepath.WalkDir` does not follow symlinks, so the checks inside `walkDir` are redundant. The top-level `os.Lstat` check is the only one that matters. The security review's TOCTOU analysis applies to `processFile` using `os.Stat` (which follows symlinks), but the attack surface is minimal.

---

## 6. Duplicate Findings

The following findings are reported by multiple reviewers as separate issues:

| Issue | Security | Architecture | Correctness |
|-------|----------|-------------|-------------|
| os.Exit(1) in RunE | F3 (LOW) | F-01 (HIGH) | F14 (MEDIUM) |
| escalationPodResources incomplete | F13 (LOW) | F-06 (MEDIUM) | Not reported |
| Suppression validation | F7 (LOW) | F-07 (LOW) | Not reported |
| Fingerprint missing file path | Not reported | F-04 (MEDIUM) | F13 (LOW) |
| Missing KC-005/KC-008/KC-009 tests | Not reported | F-11 (LOW) | F9 (LOW), F10 (MEDIUM) |

5 findings reported as duplicates across reviews, totaling 13 separate entries for 5 actual issues.

---

## 7. Blind Spots (What All Three Missed)

### BLIND_SPOT: Documentation vs. code rule ID mismatch

As detailed in section 3, the published documentation at `site/docs/reference/rules.md` describes 15 rules that do not match the 15 rules implemented in the code. The rule IDs overlap numerically (KC-001 through KC-015) but map to completely different detections. Rules the docs describe that the code does not implement include: cluster-admin binding detection as KC-003, default SA binding detection as KC-004, system SA binding detection as KC-005, wildcard API group detection as KC-006, multi-hop privilege escalation chains as KC-007, SA token escalation as KC-008, unbound role detection as KC-009, duplicate rule detection as KC-010, and empty role detection as KC-011. None of the three reviewers flagged this documentation/implementation divergence.

### BLIND_SPOT: No detection of wildcard apiGroups

The code never inspects the `apiGroups` field in RBAC rules. There is no detection for `apiGroups: ["*"]`, which the documentation claims is KC-006. A role granting `get` on `pods` in `apiGroups: ["*"]` is functionally more dangerous than the same role scoped to `apiGroups: [""]`, but the tool treats them identically. The architecture review (F-15) noted the false positive risk of not filtering apiGroups, but none of the reviews flagged the missing detection of wildcard apiGroups as a separate gap.

### BLIND_SPOT: No detection for Deployments/DaemonSets/StatefulSets/Jobs as workload types in categorize()

The `categorize()` function in `loader.go:196-252` only parses `ClusterRole`, `Role`, `ClusterRoleBinding`, `RoleBinding`, `ServiceAccount`, and `Pod` kinds. Deployment, DaemonSet, StatefulSet, Job, and CronJob are not parsed. This means the tool cannot detect privilege escalation through workload controllers at all. The security review (F13) and architecture review (F-06) flagged the incomplete `escalationPodResources` map, but neither identified that the loader does not even parse workload controller manifests, so even if the map were expanded, there would be no workload data to analyze.

### BLIND_SPOT: GitHub Action is vulnerable to argument injection

In `.github/action.yml`, `INPUT_PATHS` is split with `read -ra PATH_ARGS <<< "${INPUT_PATHS}"` and passed to the binary. `INPUT_FORMAT`, `INPUT_FAIL_ON`, and other inputs are interpolated directly into the argument list without validation. A malicious workflow input like `--fail-on "INFO" --format "sarif" -- /etc` could override earlier arguments. The security review (F4) focused on the download integrity but missed the argument injection surface in the same file. The `--` separator before `PATH_ARGS` prevents path arguments from being interpreted as flags, but the other inputs (`INPUT_FAIL_ON`, `INPUT_FORMAT`) are not validated and are placed before the separator.

### BLIND_SPOT: processFile errors silently swallowed in walkDir

At `loader.go:129`, `_ = processFile(path, opts, result)` discards the error. This means files that exceed `MaxFileSize`, fail to read, or fail to parse produce no diagnostic output. A user scanning a directory with a mix of valid and oversized manifests will get partial results with no indication of what was skipped. Combined with the missing stderr warning for empty results (correctness finding 4), the tool can silently produce incomplete scans. None of the three reviews flagged this error-swallowing pattern, though it is visible in the code they all read.

### BLIND_SPOT: No review of the release/CI pipeline security

The `ci.yml`, `release.yml`, and `docs.yml` workflows were not reviewed by any agent. For a tool that ships binaries and Docker images via goreleaser, the release pipeline is a critical supply chain component. The security review looked at `action.yml` (the consumer-facing action) but not the build/release workflows.

---

## Summary

| Category | Count |
|----------|-------|
| Severity inflation | 3 |
| Severity deflation | 2 |
| Groupthink | 2 |
| Weak evidence | 2 |
| Contradictions | 2 |
| Duplicates | 5 issues reported 13 times |
| Blind spots | 6 |

For a v0.1.0 release, the issues that actually matter:

1. **KC-014 only fires with co-located Pods** (correctness F1). Real bug, real false negatives in production use.
2. **Documentation describes different rules than the code implements.** Users will expect functionality that does not exist.
3. **No apiGroup filtering or detection.** False positives on CRDs, missing detection for wildcard apiGroups.
4. **Loader ignores workload controllers.** The tool cannot reason about Deployments/DaemonSets, which is where most real RBAC privilege escalation happens.
5. **Silent file processing failures.** Users will not know their scan is incomplete.

Everything else is legitimate quality debt but not release-blocking for a v0.1.0.
