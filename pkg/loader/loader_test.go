package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testdataDir() string {
	// Walk up from pkg/loader to find testdata
	dir, _ := filepath.Abs("../../testdata")
	return dir
}

func TestLoadDangerousDir(t *testing.T) {
	dir := filepath.Join(testdataDir(), "dangerous")
	result, err := LoadManifests([]string{dir}, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsEmpty())

	// Should have multiple ClusterRoles
	assert.NotEmpty(t, result.ClusterRoles, "expected ClusterRoles to be loaded")

	// Should have Roles (dangerous-namespace-role)
	assert.NotEmpty(t, result.Roles, "expected Roles to be loaded")

	// Should have ClusterRoleBindings
	assert.NotEmpty(t, result.ClusterRoleBindings, "expected ClusterRoleBindings to be loaded")

	// Should have RoleBindings (rolebinding-to-clusterrole, dangerous-namespace-role)
	assert.NotEmpty(t, result.RoleBindings, "expected RoleBindings to be loaded")

	// Should have ServiceAccounts
	assert.NotEmpty(t, result.ServiceAccounts, "expected ServiceAccounts to be loaded")

	// Should have Pods (cluster-admin-pod, rolebinding-to-clusterrole-pod)
	assert.NotEmpty(t, result.Pods, "expected Pods to be loaded")

	// Verify specific resources
	_, hasWildcardVerbs := result.ClusterRoles["wildcard-verbs-role"]
	assert.True(t, hasWildcardVerbs, "expected wildcard-verbs-role")

	_, hasEscalate := result.ClusterRoles["escalate-verb-role"]
	assert.True(t, hasEscalate, "expected escalate-verb-role")

	// Check that pod extracted the service account
	pod, hasPod := result.Pods["default/cluster-admin-pod"]
	if assert.True(t, hasPod, "expected cluster-admin-pod") {
		assert.Equal(t, "cluster-admin-pod-sa", pod.ServiceAccountName)
	}
}

func TestLoadCleanDir(t *testing.T) {
	dir := filepath.Join(testdataDir(), "clean")
	result, err := LoadManifests([]string{dir}, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsEmpty())

	// Verify Go template preprocessing worked
	_, hasPlaceholder := result.ClusterRoles["placeholder-value"]
	assert.True(t, hasPlaceholder, "expected Go template to be preprocessed into placeholder-value")

	// multi-doc file should extract the Role but skip ConfigMap and Service
	_, hasMultiDocRole := result.Roles["default/multi-doc-role"]
	assert.True(t, hasMultiDocRole, "expected multi-doc-role from multi-doc file")
}

func TestLoadMalformedDir(t *testing.T) {
	dir := filepath.Join(testdataDir(), "malformed")
	result, err := LoadManifests([]string{dir}, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Should not crash; malformed files are skipped gracefully
}

func TestGoTemplatePreprocessing(t *testing.T) {
	input := `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Values.name }}
  labels:
    app: {{ .Chart.Name }}
    version: {{ .Chart.Version | default "latest" }}`

	expected := goTemplateRe.ReplaceAllString(input, "placeholder-value")
	assert.NotContains(t, expected, "{{")
	assert.NotContains(t, expected, "}}")
	assert.Contains(t, expected, "placeholder-value")
}

func TestDefaultExcludes(t *testing.T) {
	// Create a temp directory structure with an excluded dir
	tmpDir := t.TempDir()

	// Create .git/config.yaml (should be excluded)
	gitDir := filepath.Join(tmpDir, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "config.yaml"), []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: should-not-load
rules: []
`), 0o644))

	// Create a valid manifest outside .git
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "valid.yaml"), []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: should-load
rules: []
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	_, hasGitFile := result.ClusterRoles["should-not-load"]
	assert.False(t, hasGitFile, ".git directory should be excluded by default")

	_, hasValid := result.ClusterRoles["should-load"]
	assert.True(t, hasValid, "valid.yaml outside .git should be loaded")
}

func TestSymlinksNotFollowed(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a real file
	realDir := filepath.Join(tmpDir, "real")
	require.NoError(t, os.MkdirAll(realDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, "role.yaml"), []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: real-role
rules: []
`), 0o644))

	// Create a symlink to the real directory
	symlinkPath := filepath.Join(tmpDir, "linked")
	require.NoError(t, os.Symlink(realDir, symlinkPath))

	// Load only the top dir: should get real-role once (from real/) and skip symlink
	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	_, hasReal := result.ClusterRoles["real-role"]
	assert.True(t, hasReal, "expected real-role from real/")
}

func TestMaxFileSizeEnforced(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file that exceeds the limit
	content := make([]byte, 100)
	for i := range content {
		content[i] = 'a'
	}
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "big.yaml"), content, 0o644))

	opts := &Options{
		MaxFileSize:        50, // very small limit
		MaxDocsPerFile:     DefaultMaxDocsPerFile,
		UseDefaultExcludes: true,
	}

	result, err := LoadManifests([]string{tmpDir}, opts)
	require.NoError(t, err)
	assert.True(t, result.IsEmpty(), "oversized file should be skipped")
}

func TestEmptyPathList(t *testing.T) {
	result, err := LoadManifests([]string{}, nil)
	require.NoError(t, err)
	assert.True(t, result.IsEmpty())
}

func TestLoadSingleFile(t *testing.T) {
	file := filepath.Join(testdataDir(), "dangerous", "wildcard-verbs.yaml")
	result, err := LoadManifests([]string{file}, nil)
	require.NoError(t, err)

	_, has := result.ClusterRoles["wildcard-verbs-role"]
	assert.True(t, has, "expected wildcard-verbs-role from single file")
}

func TestCustomExcludes(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a "custom-exclude" directory
	customDir := filepath.Join(tmpDir, "custom-exclude")
	require.NoError(t, os.MkdirAll(customDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(customDir, "role.yaml"), []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: excluded-role
rules: []
`), 0o644))

	opts := &Options{
		ExcludeDirs:        []string{"custom-exclude"},
		UseDefaultExcludes: true,
		MaxFileSize:        DefaultMaxFileSize,
		MaxDocsPerFile:     DefaultMaxDocsPerFile,
	}

	result, err := LoadManifests([]string{tmpDir}, opts)
	require.NoError(t, err)

	_, has := result.ClusterRoles["excluded-role"]
	assert.False(t, has, "custom-exclude directory should be excluded")
}

func TestServiceAccountDefaultName(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pod.yaml"), []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: no-sa-pod
  namespace: default
spec:
  containers:
  - name: app
    image: busybox
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	pod, has := result.Pods["default/no-sa-pod"]
	if assert.True(t, has) {
		assert.Equal(t, "default", pod.ServiceAccountName, "pods without explicit SA should default to 'default'")
	}
}
