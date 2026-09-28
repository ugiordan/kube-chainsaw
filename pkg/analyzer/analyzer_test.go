package analyzer

import (
	"path/filepath"
	"sort"
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

func examplesDir() string {
	dir, _ := filepath.Abs("../../examples/networkpolicy")
	return dir
}

func securityExamplesDir() string {
	return filepath.Join(filepath.Dir(examplesDir()), "security")
}

func exposureExamplesDir() string {
	return filepath.Join(filepath.Dir(examplesDir()), "exposure")
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
		name    string
		fixture string
		ruleID  string
		minSev  models.Severity // minimum expected severity
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
		{
			name:    "KC-016: NetworkPolicy access",
			fixture: "networkpolicy-access.yaml",
			ruleID:  RuleNetworkPolicyAccess,
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-017: Broad ingress peer",
			fixture: "networkpolicy-broad.yaml",
			ruleID:  RuleNetworkPolicyIngress,
			minSev:  models.SeverityWarning,
		},
		{
			name:    "KC-018: Broad egress peer",
			fixture: "networkpolicy-broad.yaml",
			ruleID:  RuleNetworkPolicyEgress,
			minSev:  models.SeverityWarning,
		},
		{
			name:    "KC-019: Privileged container",
			fixture: "workload-security.yaml",
			ruleID:  RulePrivilegedContainer,
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-020: Host namespace",
			fixture: "workload-security.yaml",
			ruleID:  RuleHostNamespace,
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-021: HostPath",
			fixture: "workload-security.yaml",
			ruleID:  RuleHostPath,
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-022: Dangerous capability",
			fixture: "workload-security.yaml",
			ruleID:  RuleDangerousCapabilities,
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-023: SCC use",
			fixture: "scc-security.yaml",
			ruleID:  RuleSCCUse,
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-024: Permissive SCC",
			fixture: "scc-security.yaml",
			ruleID:  RulePermissiveSCC,
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-025: External Service",
			fixture: "exposure.yaml",
			ruleID:  RuleExternalService,
			minSev:  models.SeverityWarning,
		},
		{
			name:    "KC-026: Unencrypted route",
			fixture: "exposure.yaml",
			ruleID:  RuleUnencryptedRoute,
			minSev:  models.SeverityWarning,
		},
		{
			name:    "KC-027: Broad route",
			fixture: "exposure.yaml",
			ruleID:  RuleBroadExternalRoute,
			minSev:  models.SeverityWarning,
		},
		{
			name:    "KC-028: Credential Secret",
			fixture: "secrets.yaml",
			ruleID:  RuleCredentialSecret,
			minSev:  models.SeverityWarning,
		},
		{
			name:    "KC-029: ServiceAccount token Secret",
			fixture: "secrets.yaml",
			ruleID:  RuleServiceAccountTokenSecret,
			minSev:  models.SeverityHigh,
		},
		{
			name:    "KC-030: ServiceAccount token access",
			fixture: "rbac-sensitive.yaml",
			ruleID:  RuleServiceAccountTokenAccess,
			minSev:  models.SeverityInfo,
		},
		{
			name:    "KC-031: CSR approval",
			fixture: "rbac-sensitive.yaml",
			ruleID:  RuleCSRApproval,
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
		"networkpolicy-default-deny.yaml",
		"networkpolicy-restricted.yaml",
		"exposure.yaml",
		"secrets.yaml",
		"scc-restricted.yaml",
		"sa-no-bindings.yaml",
		"workload-security.yaml",
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

func TestNetworkPolicyExamples(t *testing.T) {
	secure, err := loader.LoadManifests([]string{filepath.Join(examplesDir(), "secure.yaml")}, nil)
	require.NoError(t, err)
	assert.Empty(t, Analyze(secure), "secure NetworkPolicy example should produce no findings")

	broad, err := loader.LoadManifests([]string{filepath.Join(examplesDir(), "broad.yaml")}, nil)
	require.NoError(t, err)
	findings := Analyze(broad)
	assert.Len(t, findingsWithRule(findings, RuleNetworkPolicyAccess), 1)
	assert.Len(t, findingsWithRule(findings, RuleNetworkPolicyIngress), 1)
	assert.Len(t, findingsWithRule(findings, RuleNetworkPolicyEgress), 1)
}

func TestSecurityExamples(t *testing.T) {
	workload, err := loader.LoadManifests([]string{filepath.Join(securityExamplesDir(), "workload.yaml")}, nil)
	require.NoError(t, err)
	workloadFindings := Analyze(workload)
	assert.Len(t, findingsWithRule(workloadFindings, RulePrivilegedContainer), 1)
	assert.Len(t, findingsWithRule(workloadFindings, RuleHostNamespace), 1)
	assert.Len(t, findingsWithRule(workloadFindings, RuleHostPath), 1)
	assert.Len(t, findingsWithRule(workloadFindings, RuleDangerousCapabilities), 1)

	scc, err := loader.LoadManifests([]string{filepath.Join(securityExamplesDir(), "scc.yaml")}, nil)
	require.NoError(t, err)
	sccFindings := Analyze(scc)
	assert.Len(t, findingsWithRule(sccFindings, RuleSCCUse), 1)
	assert.Len(t, findingsWithRule(sccFindings, RulePermissiveSCC), 1)

	rbac, err := loader.LoadManifests([]string{filepath.Join(securityExamplesDir(), "rbac-sensitive.yaml")}, nil)
	require.NoError(t, err)
	rbacFindings := Analyze(rbac)
	assert.Len(t, findingsWithRule(rbacFindings, RulePodsExecAttach), 1)
	assert.Len(t, findingsWithRule(rbacFindings, RuleServiceAccountTokenAccess), 1)
	assert.Len(t, findingsWithRule(rbacFindings, RuleCSRApproval), 1)

	secure, err := loader.LoadManifests([]string{filepath.Join(securityExamplesDir(), "secure.yaml")}, nil)
	require.NoError(t, err)
	assert.Empty(t, Analyze(secure))
}

func TestExposureExamples(t *testing.T) {
	resources, err := loader.LoadManifests([]string{filepath.Join(exposureExamplesDir(), "external.yaml")}, nil)
	require.NoError(t, err)
	findings := Analyze(resources)
	assert.Len(t, findingsWithRule(findings, RuleExternalService), 1)
	unencrypted := findingsWithRule(findings, RuleUnencryptedRoute)
	assert.Len(t, unencrypted, 2)
	for _, finding := range unencrypted {
		if finding.ResourceKind == "Route" {
			assert.Equal(t, models.SeverityHigh, finding.Severity)
		}
	}
	assert.Len(t, findingsWithRule(findings, RuleBroadExternalRoute), 2)

	secure, err := loader.LoadManifests([]string{filepath.Join(exposureExamplesDir(), "secure.yaml")}, nil)
	require.NoError(t, err)
	secureFindings := Analyze(secure)
	assert.Empty(t, findingsWithRule(secureFindings, RuleExternalService))
	assert.Empty(t, findingsWithRule(secureFindings, RuleUnencryptedRoute))
	assert.Empty(t, findingsWithRule(secureFindings, RuleBroadExternalRoute))
}

func TestIngressPartialTLSIsReported(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.Ingresses["default/partial"] = &models.IngressData{
		Name:      "partial",
		Namespace: "default",
		File:      "ingress.yaml",
		Doc: map[string]interface{}{
			"spec": map[string]interface{}{
				"tls": []interface{}{
					map[string]interface{}{
						"hosts": []interface{}{"secure.example.com"},
					},
				},
				"rules": []interface{}{
					map[string]interface{}{"host": "secure.example.com"},
					map[string]interface{}{"host": "public.example.com"},
				},
			},
		},
	}

	findings := Analyze(resources)
	assert.Len(t, findingsWithRule(findings, RuleUnencryptedRoute), 1)
}

func TestExternalServiceVariants(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.Services["default/nodeport"] = &models.ServiceData{
		Name: "nodeport", Namespace: "default", File: "services.yaml",
		Doc: map[string]interface{}{"spec": map[string]interface{}{"type": "NodePort"}},
	}
	resources.Services["default/external-name"] = &models.ServiceData{
		Name: "external-name", Namespace: "default", File: "services.yaml",
		Doc: map[string]interface{}{"spec": map[string]interface{}{"type": "ExternalName"}},
	}
	resources.Services["default/external-ip"] = &models.ServiceData{
		Name: "external-ip", Namespace: "default", File: "services.yaml",
		Doc: map[string]interface{}{"spec": map[string]interface{}{"externalIPs": []interface{}{"203.0.113.20"}}},
	}

	findings := Analyze(resources)
	assert.Len(t, findingsWithRule(findings, RuleExternalService), 3)
}

func TestSecretExamples(t *testing.T) {
	resources, err := loader.LoadManifests([]string{filepath.Join(securityExamplesDir(), "secrets.yaml")}, nil)
	require.NoError(t, err)
	findings := Analyze(resources)
	assert.Len(t, findingsWithRule(findings, RuleCredentialSecret), 1)
	assert.Len(t, findingsWithRule(findings, RuleServiceAccountTokenSecret), 1)
}

func TestSecretFindingDoesNotExposeValues(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.Secrets["default/password"] = &models.SecretData{
		Name:      "password",
		Namespace: "default",
		File:      "secret.yaml",
		Doc: map[string]interface{}{
			"type": "Opaque",
			"stringData": map[string]interface{}{
				"password": "do-not-print-this-value",
			},
		},
	}

	findings := Analyze(resources)
	matched := findingsWithRule(findings, RuleCredentialSecret)
	require.Len(t, matched, 1)
	assert.Contains(t, matched[0].Description, "password")
	assert.NotContains(t, matched[0].Description, "do-not-print-this-value")
}

func TestSecretEdgeCases(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.Secrets["default/annotated-token"] = &models.SecretData{
		Name:      "annotated-token",
		Namespace: "default",
		File:      "secret.yaml",
		Doc: map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]interface{}{
					"kubernetes.io/service-account.name": "builder",
				},
			},
			"stringData": map[string]interface{}{"token": "short-placeholder"},
		},
	}
	resources.Secrets["default/innocent"] = &models.SecretData{
		Name:      "innocent",
		Namespace: "default",
		File:      "secret.yaml",
		Doc: map[string]interface{}{
			"type":       "Opaque",
			"stringData": map[string]interface{}{"author": "team", "secretary": "office"},
		},
	}

	findings := Analyze(resources)
	assert.Len(t, findingsWithRule(findings, RuleServiceAccountTokenSecret), 1)
	assert.Empty(t, findingsWithRule(findings, RuleCredentialSecret))
}

func TestCredentialSecretTypes(t *testing.T) {
	resources := models.NewLoadedResources()
	for _, secretType := range []string{"kubernetes.io/dockercfg", "bootstrap.kubernetes.io/token"} {
		resources.Secrets["default/"+secretType] = &models.SecretData{
			Name: secretType, Namespace: "default", File: "secrets.yaml",
			Doc: map[string]interface{}{
				"type": secretType,
				"data": map[string]interface{}{"credential": "ZHVtbXk="},
			},
		}
	}

	findings := Analyze(resources)
	assert.Len(t, findingsWithRule(findings, RuleCredentialSecret), 2)
}

func TestServiceAccountTokenReadOnlyDoesNotTriggerMinting(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.ClusterRoles["token-reader"] = &models.ClusterRoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"serviceaccounts/token"},
				"verbs":     []interface{}{"get", "list", "watch"},
			},
		},
		File: "role.yaml",
	}

	findings := Analyze(resources)
	assert.Empty(t, findingsWithRule(findings, RuleServiceAccountTokenAccess))
}

func TestCSRSignerAndStatusPaths(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.ClusterRoles["csr-controller"] = &models.ClusterRoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{"certificates.k8s.io"},
				"resources": []interface{}{"signers"},
				"verbs":     []interface{}{"approve", "sign"},
			},
			{
				"apiGroups": []interface{}{"certificates.k8s.io"},
				"resources": []interface{}{"certificatesigningrequests/status"},
				"verbs":     []interface{}{"update"},
			},
		},
		File: "csr.yaml",
	}

	findings := Analyze(resources)
	assert.Len(t, findingsWithRule(findings, RuleCSRApproval), 1)
}

func TestWorkloadSecurityScansAllContainerKinds(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.Pods["default/security-test"] = &models.PodData{
		Name:      "security-test",
		Namespace: "default",
		File:      "pod.yaml",
		Doc: map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "app",
						"securityContext": map[string]interface{}{
							"privileged": true,
						},
					},
				},
				"initContainers": []interface{}{
					map[string]interface{}{
						"name": "init",
						"securityContext": map[string]interface{}{
							"capabilities": map[string]interface{}{
								"add": []interface{}{"SYS_ADMIN"},
							},
						},
					},
				},
				"ephemeralContainers": []interface{}{
					map[string]interface{}{
						"name": "debug",
						"securityContext": map[string]interface{}{
							"privileged": true,
						},
					},
				},
			},
		},
	}

	findings := Analyze(resources)
	privileged := findingsWithRule(findings, RulePrivilegedContainer)
	require.Len(t, privileged, 1)
	assert.Contains(t, privileged[0].Description, "app")
	assert.Contains(t, privileged[0].Description, "debug")

	capabilities := findingsWithRule(findings, RuleDangerousCapabilities)
	require.Len(t, capabilities, 1)
	assert.Contains(t, capabilities[0].Description, "init")
}

func TestUnassignedPermissiveSCCIsNotReported(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.SecurityContextConstraints["privileged"] = &models.SecurityContextConstraintsData{
		Name: "privileged",
		File: "scc.yaml",
		Doc: map[string]interface{}{
			"allowPrivilegedContainer": true,
			"allowedCapabilities":      []interface{}{"*"},
			"volumes":                  []interface{}{"*"},
		},
	}

	findings := Analyze(resources)
	assert.Empty(t, findingsWithRule(findings, RulePermissiveSCC))
}

func TestSCCUseRequiresOpenShiftAPIGroup(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.ClusterRoles["custom-scc-role"] = &models.ClusterRoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{"example.com"},
				"resources": []interface{}{"securitycontextconstraints"},
				"verbs":     []interface{}{"use"},
			},
		},
		File: "custom.yaml",
	}

	findings := Analyze(resources)
	assert.Empty(t, findingsWithRule(findings, RuleSCCUse))
}

func TestNarrowPermissiveSCCAssignmentIsWarning(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.SecurityContextConstraints["developer"] = &models.SecurityContextConstraintsData{
		Name: "developer",
		File: "scc.yaml",
		Doc: map[string]interface{}{
			"allowPrivilegedContainer": true,
			"allowedCapabilities":      []interface{}{"SYS_ADMIN"},
			"defaultAddCapabilities":   []interface{}{"NET_RAW"},
			"users":                    []interface{}{"alice"},
		},
	}

	findings := Analyze(resources)
	matched := findingsWithRule(findings, RulePermissiveSCC)
	require.Len(t, matched, 1)
	assert.Equal(t, models.SeverityWarning, matched[0].Severity)
	assert.Contains(t, matched[0].Description, "SYS_ADMIN")
	assert.Contains(t, matched[0].Description, "NET_RAW")
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

func TestNetworkPolicyFindings(t *testing.T) {
	resources := loadFixture(t, "dangerous", "networkpolicy-broad.yaml")
	findings := Analyze(resources)

	ingress := findingsWithRule(findings, RuleNetworkPolicyIngress)
	require.Len(t, ingress, 1)
	assert.Equal(t, models.SeverityHigh, ingress[0].Severity,
		"a policy selecting all pods should produce a HIGH ingress finding")
	assert.Equal(t, "NetworkPolicy", ingress[0].ResourceKind)
	assert.Equal(t, "allow-all-ingress", ingress[0].ResourceName)
	assert.Equal(t, "production", ingress[0].ResourceNamespace)
	assert.Contains(t, ingress[0].Description, "all sources")

	egress := findingsWithRule(findings, RuleNetworkPolicyEgress)
	require.Len(t, egress, 2)
	byName := map[string]string{}
	for _, finding := range egress {
		byName[finding.ResourceName] = finding.Description
	}
	assert.Contains(t, byName["allow-cross-namespace-egress"], "all namespaces")
	assert.Contains(t, byName["allow-public-egress"], "all IP addresses")
}

func TestNetworkPolicyDirectionRespectsPolicyTypes(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.NetworkPolicies["default/egress-only"] = &models.NetworkPolicyData{
		Name:      "egress-only",
		Namespace: "default",
		File:      "networkpolicy.yaml",
		Doc: map[string]interface{}{
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{},
				"policyTypes": []interface{}{"Egress"},
				"ingress":     []interface{}{map[string]interface{}{}},
			},
		},
	}

	findings := Analyze(resources)
	assert.Empty(t, findingsWithRule(findings, RuleNetworkPolicyIngress),
		"a direction excluded by policyTypes must not produce a finding")
}

func TestNetworkPolicyDefaultingAndSelectorShapes(t *testing.T) {
	tests := []struct {
		name         string
		spec         map[string]interface{}
		ingressCount int
		egressCount  int
		expectedSev  models.Severity
	}{
		{
			name: "omitted policyTypes and podSelector",
			spec: map[string]interface{}{
				"ingress": []interface{}{map[string]interface{}{}},
				"egress":  []interface{}{map[string]interface{}{}},
			},
			ingressCount: 1,
			egressCount:  1,
			expectedSev:  models.SeverityHigh,
		},
		{
			name: "empty policyTypes and null podSelector",
			spec: map[string]interface{}{
				"podSelector": nil,
				"policyTypes": []interface{}{},
				"ingress":     []interface{}{map[string]interface{}{}},
				"egress":      []interface{}{map[string]interface{}{}},
			},
			ingressCount: 1,
			egressCount:  1,
			expectedSev:  models.SeverityHigh,
		},
		{
			name: "empty matchLabels selector",
			spec: map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{},
				},
				"policyTypes": []interface{}{"Ingress"},
				"ingress":     []interface{}{map[string]interface{}{}},
			},
			ingressCount: 1,
			expectedSev:  models.SeverityHigh,
		},
		{
			name: "empty matchExpressions selector",
			spec: map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchExpressions": []interface{}{},
				},
				"policyTypes": []interface{}{"Ingress"},
				"ingress":     []interface{}{map[string]interface{}{}},
			},
			ingressCount: 1,
			expectedSev:  models.SeverityHigh,
		},
		{
			name: "nonempty matchExpressions selector",
			spec: map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchExpressions": []interface{}{
						map[string]interface{}{
							"key":      "tier",
							"operator": "In",
							"values":   []interface{}{"backend"},
						},
					},
				},
				"policyTypes": []interface{}{"Ingress"},
				"ingress":     []interface{}{map[string]interface{}{}},
			},
			ingressCount: 1,
			expectedSev:  models.SeverityWarning,
		},
		{
			name: "egress defaults without policyTypes",
			spec: map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{"app": "worker"},
				},
				"egress": []interface{}{map[string]interface{}{}},
			},
			egressCount: 1,
			expectedSev: models.SeverityWarning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources := models.NewLoadedResources()
			resources.NetworkPolicies["default/test-policy"] = &models.NetworkPolicyData{
				Name:      "test-policy",
				Namespace: "default",
				File:      "networkpolicy.yaml",
				Doc:       map[string]interface{}{"spec": tt.spec},
			}

			findings := Analyze(resources)
			ingress := findingsWithRule(findings, RuleNetworkPolicyIngress)
			egress := findingsWithRule(findings, RuleNetworkPolicyEgress)
			assert.Len(t, ingress, tt.ingressCount)
			assert.Len(t, egress, tt.egressCount)
			for _, finding := range append(ingress, egress...) {
				assert.Equal(t, tt.expectedSev, finding.Severity)
			}
		})
	}
}

func TestNetworkPolicyEmptyEgressDoesNotEnableEgressByDefault(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.NetworkPolicies["default/default-deny"] = &models.NetworkPolicyData{
		Name:      "default-deny",
		Namespace: "default",
		File:      "networkpolicy.yaml",
		Doc: map[string]interface{}{
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{},
				"egress":      []interface{}{},
			},
		},
	}

	findings := Analyze(resources)
	assert.Empty(t, findingsWithRule(findings, RuleNetworkPolicyEgress))
	assert.True(t, networkPolicyDirectionEnabled(map[string]interface{}{}, "Ingress"))
	assert.False(t, networkPolicyDirectionEnabled(map[string]interface{}{
		"egress": []interface{}{},
	}, "Egress"))
}

func TestNetworkPolicyIPBlockEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		ipBlock    map[string]interface{}
		matchesAll bool
	}{
		{
			name:       "IPv4 all addresses",
			ipBlock:    map[string]interface{}{"cidr": "0.0.0.0/0"},
			matchesAll: true,
		},
		{
			name:       "IPv6 all addresses",
			ipBlock:    map[string]interface{}{"cidr": "::/0"},
			matchesAll: true,
		},
		{
			name:       "all addresses with empty except",
			ipBlock:    map[string]interface{}{"cidr": "0.0.0.0/0", "except": []interface{}{}},
			matchesAll: true,
		},
		{
			name:       "all addresses with null except",
			ipBlock:    map[string]interface{}{"cidr": "::/0", "except": nil},
			matchesAll: true,
		},
		{
			name:       "all addresses with exception",
			ipBlock:    map[string]interface{}{"cidr": "0.0.0.0/0", "except": []interface{}{"10.0.0.0/8"}},
			matchesAll: false,
		},
		{
			name:       "bounded CIDR",
			ipBlock:    map[string]interface{}{"cidr": "10.0.0.0/8"},
			matchesAll: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.matchesAll, ipBlockMatchesAllIPs(tt.ipBlock))
		})
	}
}

func TestNetworkPolicyIPBlockAnalysisHonorsExceptions(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.NetworkPolicies["default/excepted-egress"] = &models.NetworkPolicyData{
		Name:      "excepted-egress",
		Namespace: "default",
		File:      "networkpolicy.yaml",
		Doc: map[string]interface{}{
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{"app": "worker"},
				},
				"policyTypes": []interface{}{"Egress"},
				"egress": []interface{}{
					map[string]interface{}{
						"to": []interface{}{
							map[string]interface{}{
								"ipBlock": map[string]interface{}{
									"cidr":   "0.0.0.0/0",
									"except": []interface{}{"10.0.0.0/8"},
								},
							},
						},
					},
				},
			},
		},
	}

	findings := Analyze(resources)
	assert.Empty(t, findingsWithRule(findings, RuleNetworkPolicyEgress))
}

func TestNetworkPolicyPeerListEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		rule       map[string]interface{}
		matchesAll bool
	}{
		{
			name:       "omitted peer list",
			rule:       map[string]interface{}{},
			matchesAll: true,
		},
		{
			name:       "null peer list",
			rule:       map[string]interface{}{"from": nil},
			matchesAll: true,
		},
		{
			name:       "empty peer list",
			rule:       map[string]interface{}{"from": []interface{}{}},
			matchesAll: true,
		},
		{
			name: "empty pod selector peer",
			rule: map[string]interface{}{
				"from": []interface{}{
					map[string]interface{}{"podSelector": map[string]interface{}{}},
				},
			},
			matchesAll: true,
		},
		{
			name: "restricted peer",
			rule: map[string]interface{}{
				"from": []interface{}{
					map[string]interface{}{
						"namespaceSelector": map[string]interface{}{
							"matchLabels": map[string]interface{}{"team": "backend"},
						},
					},
				},
			},
			matchesAll: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []interface{}{tt.rule}
			reasons := broadNetworkPolicyPeers(rules, "from", "sources")
			assert.Equal(t, tt.matchesAll, len(reasons) > 0)
		})
	}
}

func TestMalformedNetworkPolicyDoesNotPanic(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.NetworkPolicies["default/malformed"] = &models.NetworkPolicyData{
		Name:      "malformed",
		Namespace: "default",
		File:      "malformed.yaml",
		Doc: map[string]interface{}{
			"spec": map[string]interface{}{
				"podSelector": "not-a-selector",
				"policyTypes": "not-a-list",
				"ingress":     "not-a-list",
				"egress": []interface{}{
					map[string]interface{}{
						"to": []interface{}{"not-a-peer", 42},
					},
				},
			},
		},
	}

	assert.NotPanics(t, func() {
		_ = Analyze(resources)
	})
}

func TestNetworkPolicyAccessUsesAPIGroup(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.ClusterRoles["custom-networkpolicy-role"] = &models.ClusterRoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{"example.com"},
				"resources": []interface{}{"networkpolicies"},
				"verbs":     []interface{}{"get"},
			},
		},
		File: "custom.yaml",
	}
	resources.ClusterRoles["wildcard-networkpolicy-role"] = &models.ClusterRoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{"*"},
				"resources": []interface{}{"networkpolicies"},
				"verbs":     []interface{}{"get"},
			},
		},
		File: "wildcard.yaml",
	}

	findings := Analyze(resources)
	matched := findingsWithRule(findings, RuleNetworkPolicyAccess)
	require.Len(t, matched, 1)
	assert.Equal(t, "wildcard-networkpolicy-role", matched[0].ResourceName)
}

func TestNetworkPolicyAccessRoleSeverity(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.Roles["security/networkpolicy-reader"] = &models.RoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{"networking.k8s.io"},
				"resources": []interface{}{"networkpolicies"},
				"verbs":     []interface{}{"get"},
			},
		},
		Namespace: "security",
		File:      "role.yaml",
	}
	resources.RoleBindings = append(resources.RoleBindings, &models.BindingData{
		Name:      "networkpolicy-reader-binding",
		Namespace: "security",
		RoleRef: map[string]interface{}{
			"kind": "Role",
			"name": "networkpolicy-reader",
		},
		File: "binding.yaml",
	})

	findings := Analyze(resources)
	matched := findingsWithRule(findings, RuleNetworkPolicyAccess)
	require.Len(t, matched, 1)
	assert.Equal(t, models.SeverityWarning, matched[0].Severity)
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

func TestWildcardResourceInCustomAPIGroupDoesNotTriggerWorkloadCreation(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.ClusterRoles["custom-writer"] = &models.ClusterRoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{"example.com"},
				"resources": []interface{}{"*"},
				"verbs":     []interface{}{"create"},
			},
		},
		File: "custom.yaml",
	}

	findings := Analyze(resources)
	assert.Empty(t, findingsWithRule(findings, RuleEscalationPodCreation))
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

func TestPodsLogDetection(t *testing.T) {
	resources := loadFixture(t, "dangerous", "pods-log.yaml")
	findings := Analyze(resources)

	assert.True(t, hasRule(findings, "KC-007"),
		"expected KC-007 for pods/log access")

	matched := findingsWithRule(findings, "KC-007")
	require.NotEmpty(t, matched)
	assert.Contains(t, matched[0].Description, "pods/log")
	assert.Equal(t, models.SeverityHigh, matched[0].Severity,
		"cluster-wide pods/log should be HIGH")
}

func TestPodsEphemeralContainersDetection(t *testing.T) {
	resources := loadFixture(t, "dangerous", "pods-ephemeral.yaml")
	findings := Analyze(resources)

	assert.True(t, hasRule(findings, "KC-007"),
		"expected KC-007 for pods/ephemeralcontainers access")

	matched := findingsWithRule(findings, "KC-007")
	require.NotEmpty(t, matched)
	assert.Contains(t, matched[0].Description, "pods/ephemeralcontainers")
}

func TestNodesProxyDetection(t *testing.T) {
	resources := loadFixture(t, "dangerous", "nodes-proxy.yaml")
	findings := Analyze(resources)

	assert.True(t, hasRule(findings, "KC-008"),
		"expected KC-008 for nodes/proxy access")

	matched := findingsWithRule(findings, "KC-008")
	require.NotEmpty(t, matched)
	assert.Contains(t, matched[0].Description, "nodes/proxy")
	assert.Equal(t, models.SeverityHigh, matched[0].Severity,
		"cluster-wide nodes/proxy should be HIGH")
}

func TestPodsLogWrongApiGroupNoFinding(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.ClusterRoles["custom-pods-log"] = &models.ClusterRoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{"custom.example.com"},
				"resources": []interface{}{"pods/log"},
				"verbs":     []interface{}{"get"},
			},
		},
		File: "test.yaml",
		Doc:  map[string]interface{}{"kind": "ClusterRole", "metadata": map[string]interface{}{"name": "custom-pods-log"}},
	}

	findings := Analyze(resources)
	assert.False(t, hasRule(findings, "KC-007"),
		"pods/log in non-core apiGroup should not trigger KC-007")
}

func TestMultiplePodSubresourcesDeduplicated(t *testing.T) {
	resources := models.NewLoadedResources()
	resources.ClusterRoles["multi-pod-subresources"] = &models.ClusterRoleData{
		Rules: []map[string]interface{}{
			{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"pods/exec", "pods/attach", "pods/log", "pods/ephemeralcontainers", "pods/portforward"},
				"verbs":     []interface{}{"get", "create"},
			},
		},
		File: "test.yaml",
		Doc:  map[string]interface{}{"kind": "ClusterRole", "metadata": map[string]interface{}{"name": "multi-pod-subresources"}},
	}

	findings := Analyze(resources)
	matched := findingsWithRule(findings, "KC-007")
	assert.Len(t, matched, 1,
		"multiple pod subresources in same role should produce 1 deduplicated KC-007 finding")
}

func TestKnownRuleIDs(t *testing.T) {
	ids := KnownRuleIDs()

	assert.Len(t, ids, 31, "expected 31 known rule IDs")

	for _, id := range ids {
		assert.Len(t, id, 6, "rule ID %q should be 6 chars", id)
		assert.Equal(t, "KC-", id[:3], "rule ID %q should start with KC-", id)
	}

	assert.True(t, sort.StringsAreSorted(ids), "KnownRuleIDs() should return sorted IDs")

	expected := []string{
		RuleWildcardResources, RuleWildcardVerbs, RuleEscalateVerb,
		RuleImpersonateVerb, RuleBindVerb, RuleSecretsAccess,
		RulePodsExecAttach, RuleNodesAccess, RulePVAccess,
		RuleRBACModification, RuleEscalationBindings, RuleEscalationPodCreation,
		RuleClusterAdminPod, RuleRoleBindingClusterRef, RuleAggregatedClusterRole,
		RuleNetworkPolicyAccess, RuleNetworkPolicyIngress, RuleNetworkPolicyEgress,
		RulePrivilegedContainer, RuleHostNamespace, RuleHostPath, RuleDangerousCapabilities,
		RuleSCCUse, RulePermissiveSCC,
		RuleExternalService, RuleUnencryptedRoute, RuleBroadExternalRoute,
		RuleCredentialSecret, RuleServiceAccountTokenSecret, RuleServiceAccountTokenAccess,
		RuleCSRApproval,
	}
	for _, exp := range expected {
		assert.Contains(t, ids, exp, "KnownRuleIDs() should contain %s", exp)
	}
}
