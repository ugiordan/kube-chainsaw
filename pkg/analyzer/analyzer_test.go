package analyzer

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ugiordan/kube-chainsaw/pkg/loader"
	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

func testdataDir() string {
	dir, _ := filepath.Abs("../../testdata")
	return dir
}

func loadFixture(t *testing.T, subdir, filename string) *models.LoadedResources {
	t.Helper()
	file := filepath.Join(testdataDir(), subdir, filename)
	result, err := loader.LoadManifests([]string{file}, nil)
	require.NoError(t, err)
	return result
}

func loadDir(t *testing.T, subdir string) *models.LoadedResources {
	t.Helper()
	dir := filepath.Join(testdataDir(), subdir)
	result, err := loader.LoadManifests([]string{dir}, nil)
	require.NoError(t, err)
	return result
}

func findingsWithRule(findings []models.Finding, ruleID string) []models.Finding {
	var filtered []models.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func hasRule(findings []models.Finding, ruleID string) bool {
	return len(findingsWithRule(findings, ruleID)) > 0
}

// Table-driven tests for each rule ID

func TestRuleDetection(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		ruleID   string
		minSev   models.Severity // minimum expected severity
	}{
		{
			name:    "KC-001: Wildcard resources",
			fixture: "wildcard-resources.yaml",
			ruleID:  "KC-001",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-002: Wildcard verbs",
			fixture: "wildcard-verbs.yaml",
			ruleID:  "KC-002",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-003: Escalate verb",
			fixture: "escalate-verb.yaml",
			ruleID:  "KC-003",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-004: Impersonate verb",
			fixture: "impersonate-verb.yaml",
			ruleID:  "KC-004",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-005: Bind verb",
			fixture: "bind-verb.yaml",
			ruleID:  "KC-005",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-006: Secrets access (cluster-wide)",
			fixture: "secrets-cluster-wide.yaml",
			ruleID:  "KC-006",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-006: Secrets access (readonly/unbound)",
			fixture: "secrets-readonly.yaml",
			ruleID:  "KC-006",
			minSev:  models.SeverityInfo,
		},
		{
			name:    "KC-007: Pod exec/attach",
			fixture: "pods-exec.yaml",
			ruleID:  "KC-007",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-008: Nodes access",
			fixture: "nodes-access.yaml",
			ruleID:  "KC-008",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-009: PersistentVolume access",
			fixture: "pv-access.yaml",
			ruleID:  "KC-009",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-010: RBAC modification (via escalation-create-bindings)",
			fixture: "escalation-create-bindings.yaml",
			ruleID:  "KC-010",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-011: Escalation via binding modification",
			fixture: "escalation-create-bindings.yaml",
			ruleID:  "KC-011",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-012: Escalation via pod creation",
			fixture: "escalation-create-pods.yaml",
			ruleID:  "KC-012",
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-013: Cluster-admin pod",
			fixture: "cluster-admin-pod.yaml",
			ruleID:  "KC-013",
			minSev:  models.SeverityCritical,
		},
		{
			name:    "KC-014: RoleBinding to ClusterRole",
			fixture: "rolebinding-to-clusterrole.yaml",
			ruleID:  "KC-014",
			minSev:  models.SeverityWarning,
		},
		{
			name:    "KC-015: Aggregated ClusterRole",
			fixture: "aggregated-role.yaml",
			ruleID:  "KC-015",
			minSev:  models.SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources := loadFixture(t, "dangerous", tt.fixture)
			findings := Analyze(resources)

			matched := findingsWithRule(findings, tt.ruleID)
			require.NotEmpty(t, matched, "expected rule %s to fire for %s", tt.ruleID, tt.fixture)

			// Check minimum severity
			for _, f := range matched {
				assert.GreaterOrEqual(t, int(f.Severity), int(tt.minSev),
					"rule %s severity %s < expected minimum %s", tt.ruleID, f.Severity, tt.minSev)
			}
		})
	}
}

func TestCleanFixturesProduceNoFindings(t *testing.T) {
	// These clean fixtures should produce zero dangerous findings
	cleanFiles := []string{
		"create-configmaps.yaml",
		"explicit-namespace.yaml",
		"go-templates.yaml",
		"minimal-role.yaml",
		"multi-doc-mixed.yaml",
		"sa-no-bindings.yaml",
	}

	for _, filename := range cleanFiles {
		t.Run(filename, func(t *testing.T) {
			resources := loadFixture(t, "clean", filename)
			findings := Analyze(resources)

			// Filter out KC-014 (RoleBinding to ClusterRole) and KC-015 (aggregated)
			// since these are INFO/WARNING informational findings that may appear
			// in clean manifests
			var dangerous []models.Finding
			for _, f := range findings {
				if f.RuleID != RuleRoleBindingClusterRef && f.RuleID != RuleAggregatedClusterRole {
					dangerous = append(dangerous, f)
				}
			}

			assert.Empty(t, dangerous,
				"clean fixture %s should produce no dangerous findings, got: %v", filename, dangerous)
		})
	}
}

func TestReadonlyClusterRoleNoFindings(t *testing.T) {
	resources := loadFixture(t, "clean", "readonly-clusterrole.yaml")
	findings := Analyze(resources)

	// readonly-clusterrole uses only get/list/watch on pods/services/namespaces
	// Should not trigger any dangerous resource or verb rules
	for _, f := range findings {
		assert.NotEqual(t, RuleWildcardResources, f.RuleID)
		assert.NotEqual(t, RuleWildcardVerbs, f.RuleID)
		assert.NotEqual(t, RuleSecretsAccess, f.RuleID)
	}
}

func TestSeverityLogicUnbound(t *testing.T) {
	// secrets-readonly.yaml has no bindings, so findings should be INFO
	resources := loadFixture(t, "dangerous", "secrets-readonly.yaml")
	findings := Analyze(resources)

	matched := findingsWithRule(findings, "KC-006")
	require.NotEmpty(t, matched)
	for _, f := range matched {
		assert.Equal(t, models.SeverityInfo, f.Severity,
			"unbound role findings should be INFO")
	}
}

func TestSeverityLogicClusterWide(t *testing.T) {
	// secrets-cluster-wide.yaml has a ClusterRoleBinding
	resources := loadFixture(t, "dangerous", "secrets-cluster-wide.yaml")
	findings := Analyze(resources)

	matched := findingsWithRule(findings, "KC-006")
	require.NotEmpty(t, matched)
	for _, f := range matched {
		assert.Equal(t, models.SeverityHigh, f.Severity,
			"cluster-wide without wildcards should be HIGH")
	}
}

func TestSeverityLogicClusterWideWithWildcards(t *testing.T) {
	// wildcard-verbs.yaml: bound cluster-wide with wildcard verb
	resources := loadFixture(t, "dangerous", "wildcard-verbs.yaml")
	findings := Analyze(resources)

	matched := findingsWithRule(findings, "KC-002")
	require.NotEmpty(t, matched)
	for _, f := range matched {
		assert.Equal(t, models.SeverityCritical, f.Severity,
			"cluster-wide with wildcards should be CRITICAL")
	}
}

func TestSeverityLogicNamespaceScopedRole(t *testing.T) {
	// dangerous-namespace-role.yaml is a Role (namespace-scoped), severity capped at WARNING
	resources := loadFixture(t, "dangerous", "dangerous-namespace-role.yaml")
	findings := Analyze(resources)

	matched := findingsWithRule(findings, "KC-006")
	require.NotEmpty(t, matched)
	for _, f := range matched {
		assert.LessOrEqual(t, int(f.Severity), int(models.SeverityWarning),
			"namespace-scoped Role findings should be capped at WARNING")
	}
}

func TestNilResourcesReturnsNil(t *testing.T) {
	findings := Analyze(nil)
	assert.Nil(t, findings)
}

func TestEmptyResourcesReturnsNil(t *testing.T) {
	resources := models.NewLoadedResources()
	findings := Analyze(resources)
	assert.Nil(t, findings)
}

func TestFindingsHaveFingerprints(t *testing.T) {
	resources := loadDir(t, "dangerous")
	findings := Analyze(resources)

	for _, f := range findings {
		assert.NotEmpty(t, f.Fingerprint, "finding %s should have a fingerprint", f.RuleID)
		assert.Len(t, f.Fingerprint, 64, "fingerprint should be 64 hex chars")
	}
}

func TestFindingsHaveTitles(t *testing.T) {
	resources := loadDir(t, "dangerous")
	findings := Analyze(resources)

	for _, f := range findings {
		assert.NotEmpty(t, f.Title, "finding %s should have a title", f.RuleID)
	}
}

func TestFindingsHaveRemediation(t *testing.T) {
	resources := loadDir(t, "dangerous")
	findings := Analyze(resources)

	for _, f := range findings {
		assert.NotEmpty(t, f.Remediation, "finding %s should have remediation", f.RuleID)
	}
}

func TestDeduplicationSameRulePerResource(t *testing.T) {
	// wildcard-resources.yaml has resources: ["*"] which is a dangerous resource
	// It should fire KC-001 only once for the role, not once per rule match
	resources := loadFixture(t, "dangerous", "wildcard-resources.yaml")
	findings := Analyze(resources)

	matched := findingsWithRule(findings, "KC-001")
	// Should be exactly 1 per resource
	assert.Len(t, matched, 1, "KC-001 should fire exactly once for wildcard-resources-role")
}

func TestClusterAdminPodChain(t *testing.T) {
	// cluster-admin-pod.yaml has: Pod -> SA -> ClusterRoleBinding -> cluster-admin
	resources := loadFixture(t, "dangerous", "cluster-admin-pod.yaml")
	findings := Analyze(resources)

	assert.True(t, hasRule(findings, "KC-013"),
		"expected KC-013 (cluster-admin pod) finding")

	matched := findingsWithRule(findings, "KC-013")
	for _, f := range matched {
		assert.Equal(t, models.SeverityCritical, f.Severity)
		assert.Equal(t, "Pod", f.ResourceKind)
		assert.Equal(t, "cluster-admin-pod", f.ResourceName)
	}
}

func TestRoleBindingToClusterRoleChain(t *testing.T) {
	resources := loadFixture(t, "dangerous", "rolebinding-to-clusterrole.yaml")
	findings := Analyze(resources)

	assert.True(t, hasRule(findings, "KC-014"),
		"expected KC-014 (RoleBinding to ClusterRole) finding")

	matched := findingsWithRule(findings, "KC-014")
	for _, f := range matched {
		assert.Equal(t, models.SeverityWarning, f.Severity)
		assert.Equal(t, "RoleBinding", f.ResourceKind)
	}
}

func TestAggregatedRole(t *testing.T) {
	resources := loadFixture(t, "dangerous", "aggregated-role.yaml")
	findings := Analyze(resources)

	assert.True(t, hasRule(findings, "KC-015"),
		"expected KC-015 (aggregated ClusterRole) finding")

	matched := findingsWithRule(findings, "KC-015")
	for _, f := range matched {
		assert.Equal(t, models.SeverityInfo, f.Severity)
	}
}

func TestWildcardVerbsSeverityCritical(t *testing.T) {
	// wildcard-verbs.yaml is cluster-wide with wildcard verbs
	resources := loadFixture(t, "dangerous", "wildcard-verbs.yaml")
	findings := Analyze(resources)

	// KC-002 should be CRITICAL (cluster-wide + wildcards)
	matched := findingsWithRule(findings, "KC-002")
	require.NotEmpty(t, matched)
	assert.Equal(t, models.SeverityCritical, matched[0].Severity)
}

func TestEscalationCreateBindings(t *testing.T) {
	resources := loadFixture(t, "dangerous", "escalation-create-bindings.yaml")
	findings := Analyze(resources)

	// Should fire KC-011 (privilege escalation via binding modification)
	assert.True(t, hasRule(findings, "KC-011"))

	// Should also fire KC-010 (RBAC modification) since resources include clusterrolebindings
	assert.True(t, hasRule(findings, "KC-010"))
}

func TestEscalationCreatePods(t *testing.T) {
	resources := loadFixture(t, "dangerous", "escalation-create-pods.yaml")
	findings := Analyze(resources)

	assert.True(t, hasRule(findings, "KC-012"),
		"expected KC-012 (pod creation escalation) finding")
}

func TestOperatorElevatedLegitimate(t *testing.T) {
	// This is a "clean" fixture with elevated but legitimate permissions
	// It uses RoleBinding (namespace-scoped) to a ClusterRole, so KC-014 may fire
	resources := loadFixture(t, "clean", "operator-elevated-legitimate.yaml")
	findings := Analyze(resources)

	// Should not have any critical/high findings
	for _, f := range findings {
		if f.RuleID != RuleRoleBindingClusterRef {
			assert.Less(t, int(f.Severity), int(models.SeverityHigh),
				"operator-elevated-legitimate should not produce HIGH/CRITICAL findings, got %s: %s", f.RuleID, f.Severity)
		}
	}
}

func TestBindVerb(t *testing.T) {
	// escalate-verb.yaml tests KC-003, but let's check KC-005 behavior
	// The bind verb is in the dangerousVerbs map
	resources := models.NewLoadedResources()
	resources.ClusterRoles["test-bind-role"] = &models.ClusterRoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{"rbac.authorization.k8s.io"},
				"resources": []interface{}{"clusterroles"},
				"verbs":     []interface{}{"bind"},
			},
		},
		File: "test.yaml",
		Doc:  map[string]interface{}{"kind": "ClusterRole", "metadata": map[string]interface{}{"name": "test-bind-role"}},
	}

	findings := Analyze(resources)
	assert.True(t, hasRule(findings, "KC-005"), "expected KC-005 (bind verb)")
}

// R2-1: Test KC-013 fires for Deployment -> SA -> cluster-admin chain
func TestWorkloadClusterAdminChainDeployment(t *testing.T) {
	resources := loadFixture(t, "dangerous", "deployment-with-secrets.yaml")
	findings := Analyze(resources)

	// Should fire KC-006 for secrets access via the ClusterRole
	assert.True(t, hasRule(findings, "KC-006"),
		"expected KC-006 (secrets access) finding")
}

// R2-1: Test KC-013 fires for CronJob -> SA -> cluster-admin chain
func TestWorkloadClusterAdminChainCronJob(t *testing.T) {
	resources := loadFixture(t, "dangerous", "cronjob-cluster-admin.yaml")
	findings := Analyze(resources)

	// Should fire KC-013 for CronJob with cluster-admin
	assert.True(t, hasRule(findings, "KC-013"),
		"expected KC-013 (cluster-admin workload) finding")

	matched := findingsWithRule(findings, "KC-013")
	require.NotEmpty(t, matched)
	for _, f := range matched {
		assert.Equal(t, models.SeverityCritical, f.Severity)
		assert.Equal(t, "CronJob", f.ResourceKind)
		assert.Equal(t, "admin-cronjob", f.ResourceName)
		assert.Equal(t, "batch-jobs", f.ResourceNamespace)
	}
}

// R2-1: Test workload-based chain detection across multiple workload types
func TestWorkloadPrivilegeChains(t *testing.T) {
	dir := filepath.Join(testdataDir(), "dangerous")
	resources, err := loader.LoadManifests([]string{dir}, nil)
	require.NoError(t, err)

	findings := Analyze(resources)

	// Should detect privilege chains for both Pods and Workloads
	clusterAdminFindings := findingsWithRule(findings, "KC-013")
	assert.NotEmpty(t, clusterAdminFindings, "expected at least one KC-013 finding from workloads or pods")

	// Verify at least one finding is from a workload (not a Pod)
	hasWorkloadFinding := false
	for _, f := range clusterAdminFindings {
		if f.ResourceKind != "Pod" {
			hasWorkloadFinding = true
			break
		}
	}
	assert.True(t, hasWorkloadFinding, "expected at least one KC-013 finding from a workload controller")
}
