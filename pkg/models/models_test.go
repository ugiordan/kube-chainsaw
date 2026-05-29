package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "INFO"},
		{SeverityWarning, "WARNING"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.sev.String())
		})
	}
}

func TestSeverityOrdering(t *testing.T) {
	assert.True(t, SeverityInfo < SeverityWarning)
	assert.True(t, SeverityWarning < SeverityHigh)
	assert.True(t, SeverityHigh < SeverityCritical)
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input   string
		want    Severity
		wantErr bool
	}{
		{"INFO", SeverityInfo, false},
		{"info", SeverityInfo, false},
		{"Info", SeverityInfo, false},
		{"WARNING", SeverityWarning, false},
		{"warning", SeverityWarning, false},
		{"HIGH", SeverityHigh, false},
		{"  high  ", SeverityHigh, false},
		{"CRITICAL", SeverityCritical, false},
		{"bogus", SeverityInfo, true},
		{"", SeverityInfo, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseSeverity(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestFindingFingerprint(t *testing.T) {
	f := Finding{
		RuleID:            "KC-001",
		ResourceKind:      "ClusterRole",
		ResourceName:      "test-role",
		ResourceNamespace: "default",
	}
	f.ComputeFingerprint()

	assert.NotEmpty(t, f.Fingerprint)
	assert.Len(t, f.Fingerprint, 64) // SHA256 hex is 64 chars

	// Same inputs produce the same fingerprint
	f2 := Finding{
		RuleID:            "KC-001",
		ResourceKind:      "ClusterRole",
		ResourceName:      "test-role",
		ResourceNamespace: "default",
	}
	f2.ComputeFingerprint()
	assert.Equal(t, f.Fingerprint, f2.Fingerprint)

	// Different inputs produce different fingerprints
	f3 := Finding{
		RuleID:            "KC-002",
		ResourceKind:      "ClusterRole",
		ResourceName:      "test-role",
		ResourceNamespace: "default",
	}
	f3.ComputeFingerprint()
	assert.NotEqual(t, f.Fingerprint, f3.Fingerprint)
}

func TestFindingFingerprintClusterScoped(t *testing.T) {
	f := Finding{
		RuleID:            "KC-001",
		ResourceKind:      "ClusterRole",
		ResourceName:      "test-role",
		ResourceNamespace: "", // cluster-scoped
	}
	f.ComputeFingerprint()
	assert.NotEmpty(t, f.Fingerprint)
}

func TestLoadedResourcesIsEmpty(t *testing.T) {
	r := NewLoadedResources()
	assert.True(t, r.IsEmpty())

	r.ClusterRoles["test"] = &ClusterRoleData{File: "test.yaml"}
	assert.False(t, r.IsEmpty())
}

func TestLoadedResourcesIsEmptyWithBindings(t *testing.T) {
	r := NewLoadedResources()
	assert.True(t, r.IsEmpty())

	r.ClusterRoleBindings = append(r.ClusterRoleBindings, &BindingData{Name: "test"})
	assert.False(t, r.IsEmpty())
}

func TestNewLoadedResourcesInitialized(t *testing.T) {
	r := NewLoadedResources()
	assert.NotNil(t, r.ClusterRoles)
	assert.NotNil(t, r.Roles)
	assert.NotNil(t, r.ServiceAccounts)
	assert.NotNil(t, r.Pods)
	assert.Empty(t, r.ClusterRoleBindings)
	assert.Empty(t, r.RoleBindings)
}
