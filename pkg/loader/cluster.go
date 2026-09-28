package loader

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

// ClusterOptions configures live cluster fetching.
type ClusterOptions struct {
	Namespace  string
	Kubeconfig string
}

// LoadFromCluster fetches RBAC resources, workloads, NetworkPolicies, and optional OpenShift resources from a live cluster
// via kubectl and analyzes them using the same pipeline as static manifests.
func LoadFromCluster(clusterOpts ClusterOptions) (*models.LoadedResources, error) {
	kubectlPath, err := exec.LookPath("kubectl")
	if err != nil {
		return nil, fmt.Errorf("kubectl not found in PATH: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "kube-chainsaw-cluster-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Cluster-scoped resources are always fetched globally
	if err := fetchResources(kubectlPath, "clusterroles,clusterrolebindings", "", clusterOpts.Kubeconfig, filepath.Join(tmpDir, "cluster-scoped.yaml")); err != nil {
		return nil, fmt.Errorf("fetching cluster-scoped resources: %w", err)
	}

	// Namespaced resources respect the --namespace flag
	if err := fetchResources(kubectlPath, "roles,rolebindings,serviceaccounts,services,ingresses,deployments,daemonsets,statefulsets,jobs,cronjobs,replicasets,replicationcontrollers,pods,networkpolicies", clusterOpts.Namespace, clusterOpts.Kubeconfig, filepath.Join(tmpDir, "namespaced.yaml")); err != nil {
		return nil, fmt.Errorf("fetching namespaced resources: %w", err)
	}

	// OpenShift API groups are discovered separately so vanilla Kubernetes scans do not fail.
	if err := fetchOptionalResources(kubectlPath, "securitycontextconstraints", "security.openshift.io", "", clusterOpts.Kubeconfig, filepath.Join(tmpDir, "openshift-scc.yaml")); err != nil {
		return nil, fmt.Errorf("fetching OpenShift SCC resources: %w", err)
	}
	if err := fetchOptionalResources(kubectlPath, "deploymentconfigs", "apps.openshift.io", clusterOpts.Namespace, clusterOpts.Kubeconfig, filepath.Join(tmpDir, "openshift-workloads.yaml")); err != nil {
		return nil, fmt.Errorf("fetching OpenShift workload resources: %w", err)
	}
	if err := fetchOptionalResources(kubectlPath, "routes", "route.openshift.io", clusterOpts.Namespace, clusterOpts.Kubeconfig, filepath.Join(tmpDir, "openshift-routes.yaml")); err != nil {
		return nil, fmt.Errorf("fetching OpenShift Route resources: %w", err)
	}

	loaderOpts := DefaultOptions()
	loaderOpts.UseDefaultExcludes = false
	return LoadManifests([]string{tmpDir}, loaderOpts)
}

func fetchOptionalResources(kubectlPath, resources, apiGroup, namespace, kubeconfig, outputPath string) error {
	args := []string{"api-resources", "--api-group", apiGroup, "-o", "name"}
	if kubeconfig != "" {
		args = append(args, "--kubeconfig", kubeconfig)
	}

	out, err := exec.Command(kubectlPath, args...).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: unable to discover optional API group %q: %v\n", apiGroup, err)
		return nil
	}
	if !optionalResourceAvailable(string(out), resources, apiGroup) {
		return nil
	}

	if err := fetchResources(kubectlPath, resources, namespace, kubeconfig, outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: unable to fetch optional resource %q: %v\n", resources, err)
	}
	return nil
}

func optionalResourceAvailable(output, resource, apiGroup string) bool {
	expectedQualifiedName := resource + "." + apiGroup
	for _, line := range strings.Fields(output) {
		if line == resource || line == expectedQualifiedName {
			return true
		}
	}
	return false
}

func fetchResources(kubectlPath, resources, namespace, kubeconfig, outputPath string) error {
	args := []string{"get", resources, "-o", "yaml"}

	if namespace != "" {
		args = append(args, "-n", namespace)
	} else {
		args = append(args, "-A")
	}

	if kubeconfig != "" {
		args = append(args, "--kubeconfig", kubeconfig)
	}

	cmd := exec.Command(kubectlPath, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("kubectl failed: %s", string(exitErr.Stderr))
		}
		return fmt.Errorf("kubectl failed: %w", err)
	}

	return os.WriteFile(outputPath, out, 0600)
}
