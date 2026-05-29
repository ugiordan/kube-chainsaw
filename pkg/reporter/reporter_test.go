package reporter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

func sampleFindings() []models.Finding {
	f1 := models.Finding{
		RuleID:            "KC-001",
		Severity:          models.SeverityCritical,
		Title:             "Wildcard resource access",
		File:              "manifests/cluster-admin.yaml",
		Description:       "Role \"admin\" has wildcard resource access",
		Remediation:       "Replace wildcard (*) resources with explicit resource names",
		ResourceKind:      "ClusterRole",
		ResourceName:      "admin",
		ResourceNamespace: "",
	}
	f1.ComputeFingerprint()

	f2 := models.Finding{
		RuleID:            "KC-006",
		Severity:          models.SeverityHigh,
		Title:             "Secrets access",
		File:              "manifests/reader.yaml",
		Description:       "Role \"reader\" grants access to secrets",
		Remediation:       "Restrict secrets access to specific namespaces",
		ResourceKind:      "Role",
		ResourceName:      "reader",
		ResourceNamespace: "production",
	}
	f2.ComputeFingerprint()

	f3 := models.Finding{
		RuleID:            "KC-015",
		Severity:          models.SeverityInfo,
		Title:             "Aggregated ClusterRole detected",
		File:              "manifests/agg.yaml",
		Description:       "ClusterRole uses aggregation labels",
		Remediation:       "Review aggregation labels",
		ResourceKind:      "ClusterRole",
		ResourceName:      "agg-role",
		ResourceNamespace: "",
		Suppressed:        true,
	}
	f3.ComputeFingerprint()

	return []models.Finding{f1, f2, f3}
}

func TestConsoleReporter_EmptyFindings(t *testing.T) {
	r := &ConsoleReporter{}
	out, err := r.Render(nil)
	require.NoError(t, err)
	assert.Equal(t, "No findings.\n", out)
}

func TestConsoleReporter_Render(t *testing.T) {
	r := &ConsoleReporter{}
	out, err := r.Render(sampleFindings())
	require.NoError(t, err)

	// CRITICAL section comes first
	critIdx := strings.Index(out, "=== CRITICAL ===")
	highIdx := strings.Index(out, "=== HIGH ===")
	infoIdx := strings.Index(out, "=== INFO ===")
	assert.True(t, critIdx < highIdx, "CRITICAL should appear before HIGH")
	assert.True(t, highIdx < infoIdx, "HIGH should appear before INFO")

	// Content checks
	assert.Contains(t, out, "[KC-001]")
	assert.Contains(t, out, "Wildcard resource access")
	assert.Contains(t, out, "manifests/cluster-admin.yaml")
	assert.Contains(t, out, "ClusterRole/admin")
	assert.Contains(t, out, "[SUPPRESSED]")
	assert.Contains(t, out, "Total: 3 findings (1 suppressed)")
}

func TestJSONReporter_Render(t *testing.T) {
	r := &JSONReporter{}
	out, err := r.Render(sampleFindings())
	require.NoError(t, err)

	// Verify it's valid JSON
	var parsed jsonReport
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	assert.Len(t, parsed.Findings, 3)
	assert.Equal(t, "KC-001", parsed.Findings[0].RuleID)
	assert.Equal(t, "CRITICAL", parsed.Findings[0].Severity)
	assert.Equal(t, "KC-006", parsed.Findings[1].RuleID)
	assert.Equal(t, "HIGH", parsed.Findings[1].Severity)
	assert.Equal(t, "production", parsed.Findings[1].ResourceNamespace)
	assert.True(t, parsed.Findings[2].Suppressed)
	assert.NotEmpty(t, parsed.Findings[0].Fingerprint)
}

func TestJSONReporter_EmptyFindings(t *testing.T) {
	r := &JSONReporter{}
	out, err := r.Render(nil)
	require.NoError(t, err)

	var parsed jsonReport
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)
	assert.Len(t, parsed.Findings, 0)
}

func TestSARIFReporter_Render(t *testing.T) {
	r := &SARIFReporter{}
	out, err := r.Render(sampleFindings())
	require.NoError(t, err)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(out), &parsed)
	require.NoError(t, err)

	// Check SARIF structure
	assert.Equal(t, "2.1.0", parsed["version"])
	assert.Contains(t, out, "kube-chainsaw")

	// Verify runs exist
	runs, ok := parsed["runs"].([]interface{})
	require.True(t, ok)
	require.Len(t, runs, 1)

	run := runs[0].(map[string]interface{})

	// Verify tool info
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	assert.Equal(t, "kube-chainsaw", driver["name"])

	// Verify rules
	rules := driver["rules"].([]interface{})
	assert.Len(t, rules, 3)

	// Verify results
	results := run["results"].([]interface{})
	assert.Len(t, results, 3)

	// Check first result level
	firstResult := results[0].(map[string]interface{})
	assert.Equal(t, "error", firstResult["level"])
	assert.Equal(t, "KC-001", firstResult["ruleId"])

	// Check suppression on third result
	thirdResult := results[2].(map[string]interface{})
	suppressions, ok := thirdResult["suppressions"].([]interface{})
	require.True(t, ok)
	assert.Len(t, suppressions, 1)
}

func TestSARIFReporter_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity models.Severity
		expected string
	}{
		{models.SeverityCritical, "error"},
		{models.SeverityHigh, "error"},
		{models.SeverityWarning, "warning"},
		{models.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, severityToSARIFLevel(tt.severity))
		})
	}
}
