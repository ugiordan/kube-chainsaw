package suppression

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

func TestLoadSuppressions_ValidFile(t *testing.T) {
	content := `suppressions:
  - rule_id: KC-001
    resource_name: admin
    reason: "Known admin role, accepted risk"
  - rule_id: KC-006
    resource_name: reader
    resource_namespace: production
    reason: "Secrets reader is expected"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	sups, err := LoadSuppressions(path)
	require.NoError(t, err)
	assert.Len(t, sups, 2)
	assert.Equal(t, "KC-001", sups[0].RuleID)
	assert.Equal(t, "admin", sups[0].ResourceName)
	assert.Equal(t, "", sups[0].ResourceNamespace)
	assert.Equal(t, "Known admin role, accepted risk", sups[0].Reason)
	assert.Equal(t, "production", sups[1].ResourceNamespace)
}

func TestLoadSuppressions_FileNotFound(t *testing.T) {
	_, err := LoadSuppressions("/nonexistent/file.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read suppressions file")
}

func TestLoadSuppressions_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{{not yaml"), 0644))

	_, err := LoadSuppressions(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse suppressions file")
}

func TestApplySuppressions_BasicMatch(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "KC-001", ResourceName: "admin", ResourceNamespace: ""},
		{RuleID: "KC-006", ResourceName: "reader", ResourceNamespace: "production"},
	}
	suppressions := []Suppression{
		{RuleID: "KC-001", ResourceName: "admin"},
	}

	result := ApplySuppressions(findings, suppressions)
	assert.True(t, result[0].Suppressed, "admin should be suppressed")
	assert.False(t, result[1].Suppressed, "reader should not be suppressed")
}

func TestApplySuppressions_NamespaceScoped(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "KC-006", ResourceName: "reader", ResourceNamespace: "production"},
		{RuleID: "KC-006", ResourceName: "reader", ResourceNamespace: "staging"},
	}
	suppressions := []Suppression{
		{RuleID: "KC-006", ResourceName: "reader", ResourceNamespace: "production"},
	}

	result := ApplySuppressions(findings, suppressions)
	assert.True(t, result[0].Suppressed, "production/reader should be suppressed")
	assert.False(t, result[1].Suppressed, "staging/reader should NOT be suppressed")
}

func TestApplySuppressions_WildcardNamespace(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "KC-006", ResourceName: "reader", ResourceNamespace: "production"},
		{RuleID: "KC-006", ResourceName: "reader", ResourceNamespace: "staging"},
		{RuleID: "KC-006", ResourceName: "reader", ResourceNamespace: ""},
	}
	suppressions := []Suppression{
		{RuleID: "KC-006", ResourceName: "reader"}, // no namespace = wildcard
	}

	result := ApplySuppressions(findings, suppressions)
	assert.True(t, result[0].Suppressed, "production/reader should be suppressed (wildcard ns)")
	assert.True(t, result[1].Suppressed, "staging/reader should be suppressed (wildcard ns)")
	assert.True(t, result[2].Suppressed, "cluster-scoped reader should be suppressed (wildcard ns)")
}

func TestApplySuppressions_NoMatch(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "KC-001", ResourceName: "admin"},
	}
	suppressions := []Suppression{
		{RuleID: "KC-002", ResourceName: "admin"},           // wrong rule
		{RuleID: "KC-001", ResourceName: "different-admin"}, // wrong name
	}

	result := ApplySuppressions(findings, suppressions)
	assert.False(t, result[0].Suppressed, "should not match any suppression")
}

func TestApplySuppressions_SuppressedFindingsStayInList(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "KC-001", ResourceName: "admin"},
		{RuleID: "KC-006", ResourceName: "reader"},
	}
	suppressions := []Suppression{
		{RuleID: "KC-001", ResourceName: "admin"},
		{RuleID: "KC-006", ResourceName: "reader"},
	}

	result := ApplySuppressions(findings, suppressions)
	assert.Len(t, result, 2, "suppressed findings should remain in the list")
	assert.True(t, result[0].Suppressed)
	assert.True(t, result[1].Suppressed)
}

func TestApplySuppressions_EmptyInputs(t *testing.T) {
	// Empty findings
	result := ApplySuppressions(nil, []Suppression{{RuleID: "KC-001", ResourceName: "x"}})
	assert.Nil(t, result)

	// Empty suppressions
	findings := []models.Finding{{RuleID: "KC-001", ResourceName: "admin"}}
	result = ApplySuppressions(findings, nil)
	assert.False(t, result[0].Suppressed)
}

func TestLoadSuppressions_EmptyRuleID(t *testing.T) {
	content := `suppressions:
  - rule_id: ""
    resource_name: admin
`
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	_, err := LoadSuppressions(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty rule_id")
}

func TestLoadSuppressions_EmptyResourceName(t *testing.T) {
	content := `suppressions:
  - rule_id: KC-001
    resource_name: ""
`
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	_, err := LoadSuppressions(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty resource_name")
}

func TestLoadSuppressions_FileTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.yaml")
	// Create a file that exceeds the 1MB limit
	data := make([]byte, MaxSuppressionFileSize+1)
	for i := range data {
		data[i] = 'a'
	}
	require.NoError(t, os.WriteFile(path, data, 0644))

	_, err := LoadSuppressions(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}
