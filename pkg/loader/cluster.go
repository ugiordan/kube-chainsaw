package loader

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

// ClusterOptions configures live cluster fetching.
type ClusterOptions struct {
	Namespace  string
	Kubeconfig string
}

// LoadFromCluster fetches RBAC resources and workloads from a live cluster
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
	defer os.RemoveAll(tmpDir)

	// Cluster-scoped resources are always fetched globally
	if err := fetchResources(kubectlPath, "clusterroles,clusterrolebindings", "", clusterOpts.Kubeconfig, filepath.Join(tmpDir, "cluster-scoped.yaml")); err != nil {
		return nil, fmt.Errorf("fetching cluster-scoped resources: %w", err)
	}

	// Namespaced resources respect the --namespace flag
	if err := fetchResources(kubectlPath, "roles,rolebindings,serviceaccounts,deployments,daemonsets,statefulsets,jobs,cronjobs,replicasets,pods", clusterOpts.Namespace, clusterOpts.Kubeconfig, filepath.Join(tmpDir, "namespaced.yaml")); err != nil {
		return nil, fmt.Errorf("fetching namespaced resources: %w", err)
	}

	loaderOpts := DefaultOptions()
	loaderOpts.UseDefaultExcludes = false
	return LoadManifests([]string{tmpDir}, loaderOpts)
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
