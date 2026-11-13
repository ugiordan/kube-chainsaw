package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ugiordan/kube-chainsaw/pkg/analyzer"
	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

func TestIndependentGroupBindings(t *testing.T) {
	for name, subject := range map[string]map[string]interface{}{
		"direct control":       {"kind": "ServiceAccount", "name": "sa", "namespace": "default"},
		"namespace group":      {"kind": "Group", "name": "system:serviceaccounts:default"},
		"all service accounts": {"kind": "Group", "name": "system:serviceaccounts"},
		"authenticated":        {"kind": "Group", "name": "system:authenticated"},
		"user identity":        {"kind": "User", "name": "system:serviceaccount:default:sa"},
	} {
		t.Run(name, func(t *testing.T) {
			r := models.NewLoadedResources()
			r.Pods["default/pod"] = &models.PodData{Name: "pod", Namespace: "default", ServiceAccountName: "sa"}
			r.ClusterRoleBindings = append(r.ClusterRoleBindings, &models.BindingData{Name: "admin", RoleRef: map[string]interface{}{"kind": "ClusterRole", "name": "cluster-admin"}, Subjects: []map[string]interface{}{subject}})
			var found bool
			for _, f := range analyzer.Analyze(r) {
				if f.RuleID == analyzer.RuleClusterAdminPod {
					found = true
				}
			}
			require.True(t, found, "cluster-admin grant must be linked to pod")
		})
	}
}
