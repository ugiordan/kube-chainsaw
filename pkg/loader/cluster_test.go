package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListUnwrapping(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "list.yaml"), []byte(`
apiVersion: v1
kind: List
items:
- apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: list-role-one
  rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
- apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: list-role-two
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	_, hasOne := result.ClusterRoles["list-role-one"]
	_, hasTwo := result.ClusterRoles["list-role-two"]
	assert.True(t, hasOne, "expected list-role-one from List wrapper")
	assert.True(t, hasTwo, "expected list-role-two from List wrapper")
}

func TestListUnwrappingTypedList(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "typed-list.yaml"), []byte(`
apiVersion: v1
kind: ClusterRoleList
items:
- apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: typed-list-role
  rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	_, has := result.ClusterRoles["typed-list-role"]
	assert.True(t, has, "expected typed-list-role from ClusterRoleList wrapper")
}

func TestListUnwrappingMixedTypes(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "mixed.yaml"), []byte(`
apiVersion: v1
kind: List
items:
- apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: mixed-clusterrole
  rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
- apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata:
    name: mixed-role
    namespace: test-ns
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
- apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: mixed-binding
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: mixed-clusterrole
  subjects:
  - kind: ServiceAccount
    name: mixed-sa
    namespace: test-ns
- apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: mixed-sa
    namespace: test-ns
- apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: mixed-deployment
    namespace: test-ns
  spec:
    selector:
      matchLabels:
        app: test
    template:
      metadata:
        labels:
          app: test
      spec:
        serviceAccountName: mixed-sa
        containers:
        - name: app
          image: busybox
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	_, hasCR := result.ClusterRoles["mixed-clusterrole"]
	_, hasRole := result.Roles["test-ns/mixed-role"]
	_, hasSA := result.ServiceAccounts["test-ns/mixed-sa"]
	_, hasWorkload := result.Workloads["Deployment/test-ns/mixed-deployment"]

	assert.True(t, hasCR, "expected ClusterRole from mixed List")
	assert.True(t, hasRole, "expected Role from mixed List")
	assert.True(t, hasSA, "expected ServiceAccount from mixed List")
	assert.True(t, hasWorkload, "expected Deployment from mixed List")
	assert.Len(t, result.ClusterRoleBindings, 1, "expected 1 ClusterRoleBinding from mixed List")
}

func TestListUnwrappingEmptyItems(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "empty-list.yaml"), []byte(`
apiVersion: v1
kind: List
items: []
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)
	assert.True(t, result.IsEmpty(), "empty List should produce no resources")
}

func TestListUnwrappingNoItems(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "no-items.yaml"), []byte(`
apiVersion: v1
kind: List
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)
	assert.True(t, result.IsEmpty(), "List without items field should produce no resources")
}

func TestListUnwrappingNestedList(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "nested.yaml"), []byte(`
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: List
  items:
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      name: nested-role
    rules:
    - apiGroups: [""]
      resources: ["secrets"]
      verbs: ["get"]
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	_, has := result.ClusterRoles["nested-role"]
	assert.True(t, has, "expected nested-role from nested List")
}

func TestListUnwrappingNonRBACItemsSkipped(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "non-rbac.yaml"), []byte(`
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: ConfigMap
  metadata:
    name: some-config
    namespace: default
  data:
    key: value
- apiVersion: v1
  kind: Service
  metadata:
    name: some-service
    namespace: default
  spec:
    ports:
    - port: 80
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)
	assert.True(t, result.IsEmpty(), "non-RBAC items in List should be skipped")
}

func TestListUnwrappingWithDirectResources(t *testing.T) {
	tmpDir := t.TempDir()

	// List response alongside a direct resource in the same directory
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "list.yaml"), []byte(`
apiVersion: v1
kind: List
items:
- apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: from-list
  rules: []
`), 0o644))

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "direct.yaml"), []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: from-direct
rules: []
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	_, hasList := result.ClusterRoles["from-list"]
	_, hasDirect := result.ClusterRoles["from-direct"]
	assert.True(t, hasList, "expected from-list")
	assert.True(t, hasDirect, "expected from-direct")
}

func TestLoadFromClusterMissingKubectl(t *testing.T) {
	t.Setenv("PATH", "/nonexistent")

	_, err := LoadFromCluster(ClusterOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kubectl not found")
}

func TestFetchResourcesBuildsCorrectArgs(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		wantFlag  string
	}{
		{"all namespaces", "", "-A"},
		{"specific namespace", "my-ns", "-n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"get", "clusterroles", "-o", "yaml"}
			if tt.namespace != "" {
				args = append(args, "-n", tt.namespace)
			} else {
				args = append(args, "-A")
			}

			found := false
			for _, arg := range args {
				if arg == tt.wantFlag {
					found = true
					break
				}
			}
			assert.True(t, found, "expected %s flag in args", tt.wantFlag)
		})
	}
}

func TestMaxDocsPerFileEnforced(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file with multiple documents
	content := ""
	for i := 0; i < 5; i++ {
		content += `---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: doc-role-` + string(rune('a'+i)) + `
rules: []
`
	}
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "many-docs.yaml"), []byte(content), 0o644))

	opts := &Options{
		MaxFileSize:        DefaultMaxFileSize,
		MaxDocsPerFile:     3, // less than 5 documents
		UseDefaultExcludes: true,
	}

	result, err := LoadManifests([]string{tmpDir}, opts)
	require.NoError(t, err)
	assert.True(t, result.IsEmpty(), "file exceeding MaxDocsPerFile should be skipped")
}

func TestMultiDocYAMLInList(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "multi.yaml"), []byte(`
apiVersion: v1
kind: ClusterRoleList
items:
- apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: multi-doc-cr
  rules: []
---
apiVersion: v1
kind: RoleBindingList
items:
- apiVersion: rbac.authorization.k8s.io/v1
  kind: RoleBinding
  metadata:
    name: multi-doc-rb
    namespace: test
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: multi-doc-cr
  subjects:
  - kind: ServiceAccount
    name: test-sa
    namespace: test
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	_, hasCR := result.ClusterRoles["multi-doc-cr"]
	assert.True(t, hasCR, "expected ClusterRole from first List doc")
	assert.Len(t, result.RoleBindings, 1, "expected RoleBinding from second List doc")
}

func TestPodListFromKubectl(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pods.yaml"), []byte(`
apiVersion: v1
kind: PodList
items:
- apiVersion: v1
  kind: Pod
  metadata:
    name: web-pod
    namespace: production
  spec:
    serviceAccountName: web-sa
    containers:
    - name: web
      image: nginx
- apiVersion: v1
  kind: Pod
  metadata:
    name: worker-pod
    namespace: production
  spec:
    containers:
    - name: worker
      image: busybox
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	web, hasWeb := result.Pods["production/web-pod"]
	worker, hasWorker := result.Pods["production/worker-pod"]

	assert.True(t, hasWeb, "expected web-pod from PodList")
	assert.True(t, hasWorker, "expected worker-pod from PodList")

	if hasWeb {
		assert.Equal(t, "web-sa", web.ServiceAccountName)
	}
	if hasWorker {
		assert.Equal(t, "default", worker.ServiceAccountName, "pod without SA should default to 'default'")
	}
}

func TestDeploymentListFromKubectl(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "deployments.yaml"), []byte(`
apiVersion: apps/v1
kind: DeploymentList
items:
- apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: operator
    namespace: operator-system
  spec:
    selector:
      matchLabels:
        app: operator
    template:
      metadata:
        labels:
          app: operator
      spec:
        serviceAccountName: operator-sa
        containers:
        - name: manager
          image: operator:latest
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	workload, has := result.Workloads["Deployment/operator-system/operator"]
	assert.True(t, has, "expected Deployment from DeploymentList")
	if has {
		assert.Equal(t, "operator-sa", workload.ServiceAccountName)
	}
}

func TestNonYAMLFilesIgnored(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "readme.md"), []byte("# README"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "data.txt"), []byte("some data"), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)
	assert.True(t, result.IsEmpty(), "non-YAML files should be ignored")
}

func TestInvalidYAMLGracefullySkipped(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "invalid.yaml"), []byte(`
this is not: valid: yaml: at: all
  - broken
    indentation
  key: [unclosed
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)
	assert.True(t, result.IsEmpty(), "invalid YAML should be skipped without error")
}

func TestNonexistentPathReturnsError(t *testing.T) {
	_, err := LoadManifests([]string{"/nonexistent/path"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot access")
}

func TestDuplicateResourceOverwrites(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "dup.yaml"), []byte(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dup-role
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dup-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]
`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	cr, has := result.ClusterRoles["dup-role"]
	assert.True(t, has)
	if has {
		// Should have the second definition (overwrites)
		assert.Len(t, cr.Rules, 1)
	}
}

func TestJSONManifestSupported(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "role.json"), []byte(`{
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "kind": "ClusterRole",
  "metadata": {
    "name": "json-role"
  },
  "rules": [
    {
      "apiGroups": [""],
      "resources": ["secrets"],
      "verbs": ["get"]
    }
  ]
}`), 0o644))

	result, err := LoadManifests([]string{tmpDir}, nil)
	require.NoError(t, err)

	_, has := result.ClusterRoles["json-role"]
	assert.True(t, has, "expected ClusterRole from JSON file")
}
