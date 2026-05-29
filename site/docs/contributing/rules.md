# Adding Detection Rules

Learn how to add new detection rules to kube-chainsaw.

---

## Rule Structure

Detection rules are defined in `pkg/analyzer/rules.go`. Each rule has:

- **Rule ID**: Unique identifier (KC-001 through KC-015)
- **Description**: Human-readable title
- **Remediation**: How to fix the issue
- **Detection logic**: Implemented in `pkg/analyzer/analyzer.go`

---

## Rule Definition

Add constants and mappings to `pkg/analyzer/rules.go`:

```go
const (
	RuleWildcardResources     = "KC-001"
	RuleWildcardVerbs         = "KC-002"
	// ... existing rules ...
	RuleNewRule               = "KC-016"  // New rule
)

// Add to ruleDescriptions
var ruleDescriptions = map[string]string{
	RuleWildcardResources: "Wildcard resource access",
	// ... existing rules ...
	RuleNewRule:           "New rule description",
}

// Add to ruleRemediations
var ruleRemediations = map[string]string{
	RuleWildcardResources: "Replace wildcard (*) resources with explicit resource names",
	// ... existing rules ...
	RuleNewRule:           "Remediation guidance",
}
```

---

## Detection Logic

Implement detection logic in `pkg/analyzer/analyzer.go`. There are two main patterns:

### Pattern 1: Rule-level detection

Add to a `dangerousVerbs` or `dangerousResources` map:

```go
var dangerousVerbs = map[string]string{
	"*":           RuleWildcardVerbs,
	"escalate":    RuleEscalateVerb,
	"impersonate": RuleImpersonateVerb,
	"bind":        RuleBindVerb,
	"delete":      RuleNewRule,  // New rule
}
```

### Pattern 2: Custom detection function

Add custom logic in the appropriate phase:

```go
// In checkRules() function
for _, rule := range rules {
	verbs := toStringSlice(rule["verbs"])
	resources := toStringSlice(rule["resources"])
	apiGroups := toStringSlice(rule["apiGroups"])

	// New rule: detect specific pattern
	if contains(verbs, "delete") && contains(resources, "namespaces") {
		dedup := RuleNewRule + "|" + roleName
		if !seen[dedup] {
			seen[dedup] = true
			sev := computeSeverity(scope, hasWildcards)
			if isNamespaced {
				sev = capSeverity(sev, models.SeverityWarning)
			}
			f := newFinding(RuleNewRule, sev, file, roleKind, roleName, namespace)
			f.Description = fmt.Sprintf("Role %q can delete namespaces", roleName)
			findings = append(findings, f)
		}
	}
}
```

---

## Example: Pod Eviction Rule

Add a new rule to detect `create` verb on `pods/eviction`:

**Step 1:** Add constants to `pkg/analyzer/rules.go`:

```go
const (
	// ... existing rules ...
	RulePodEviction = "KC-016"
)

var dangerousResources = map[string]string{
	"*":                   RuleWildcardResources,
	"secrets":             RuleSecretsAccess,
	// ... existing rules ...
	"pods/eviction":       RulePodEviction,  // New rule
}

var ruleDescriptions = map[string]string{
	// ... existing rules ...
	RulePodEviction: "Pod eviction permission",
}

var ruleRemediations = map[string]string{
	// ... existing rules ...
	RulePodEviction: "Restrict pods/eviction to cluster administrators",
}
```

**Step 2:** Add to core group resources (if applicable):

```go
var coreGroupResources = map[string]bool{
	"secrets":           true,
	"pods/exec":         true,
	"pods/attach":       true,
	"nodes":             true,
	"persistentvolumes": true,
	"pods/eviction":     true,  // New rule
}
```

That's it! The existing detection logic in `checkRules()` will automatically trigger KC-016 when it encounters the `pods/eviction` resource.

---

## Testing Rules

Create a test fixture in `tests/fixtures/`:

**tests/fixtures/kc016_pod_eviction.yaml:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-evictor
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]
```

Add a test in the appropriate test file:

```go
func TestPodEvictionDetection(t *testing.T) {
	opts := loader.DefaultOptions()
	resources, err := loader.LoadManifests([]string{"../../tests/fixtures/kc016_pod_eviction.yaml"}, opts)
	if err != nil {
		t.Fatalf("Failed to load manifests: %v", err)
	}

	findings := analyzer.Analyze(resources)

	// Filter to KC-016 findings
	var kc016Findings []models.Finding
	for _, f := range findings {
		if f.RuleID == "KC-016" {
			kc016Findings = append(kc016Findings, f)
		}
	}

	if len(kc016Findings) != 1 {
		t.Errorf("Expected 1 KC-016 finding, got %d", len(kc016Findings))
	}

	if kc016Findings[0].ResourceName != "pod-evictor" {
		t.Errorf("Expected resource name 'pod-evictor', got %q", kc016Findings[0].ResourceName)
	}
}
```

Run the test:

```bash
go test ./pkg/analyzer -run TestPodEvictionDetection
```

---

## Rule ID Conventions

- Core rules: `KC-001` through `KC-999`
- Sequential numbering (next available: KC-016)

---

## Severity Guidelines

| Severity | Use When |
|----------|----------|
| CRITICAL | Direct path to cluster-admin or privilege escalation chains |
| HIGH | Dangerous permissions or misconfigurations (wildcard verbs, secret access) |
| WARNING | Overly broad permissions or policy violations |
| INFO | Best practice violations or informational findings |

Severity is computed dynamically based on binding scope (see `computeSeverity` in `analyzer.go`).

---

## Documentation

Add a rule description to `site/docs/reference/rules.md`:

```markdown
## KC-016: Pod Eviction Permission

**Severity:** Varies by binding scope

**Description:** Detects `create` verb on `pods/eviction` subresource. Pod eviction allows terminating pods, potentially disrupting workloads.

**Impact:** Allows eviction of pods, which can be used to disrupt services or trigger workload rescheduling.

**Example:**

​```yaml
rules:
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]
​```

**Recommendation:** Restrict `pods/eviction` to cluster administrators.
```

---

## Pull Request Checklist

Before submitting a PR:

- [ ] Rule constants added to `rules.go`
- [ ] Detection logic added to `analyzer.go` (or leverages existing pattern)
- [ ] Test fixture and test case added
- [ ] All tests pass (`go test ./...`)
- [ ] Code formatted (`go fmt ./...`)
- [ ] Linting passes (`go vet ./...`)
- [ ] Documentation added to `rules.md`

---

## Next Steps

- [Development Setup](setup.md): Set up local environment
- [Architecture](../architecture/overview.md): Understand the codebase
- [Detection Rules Reference](../reference/rules.md): See existing rules
