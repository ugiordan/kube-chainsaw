package analyzer

import (
	"sort"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

// Rule IDs and their descriptions.
const (
	RuleWildcardResources     = "KC-001"
	RuleWildcardVerbs         = "KC-002"
	RuleEscalateVerb          = "KC-003"
	RuleImpersonateVerb       = "KC-004"
	RuleBindVerb              = "KC-005"
	RuleSecretsAccess         = "KC-006"
	RulePodsExecAttach        = "KC-007"
	RuleNodesAccess           = "KC-008"
	RulePVAccess              = "KC-009"
	RuleRBACModification      = "KC-010"
	RuleEscalationBindings    = "KC-011"
	RuleEscalationPodCreation = "KC-012"
	RuleClusterAdminPod       = "KC-013"
	RuleRoleBindingClusterRef = "KC-014"
	RuleAggregatedClusterRole = "KC-015"
)

// KnownRuleIDs returns all valid KC rule IDs. Used by external integrations
// (e.g., kube-linter template) for dynamic parameter validation.
func KnownRuleIDs() []string {
	ids := make([]string, 0, len(ruleDescriptions))
	for id := range ruleDescriptions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// dangerousVerbs maps verbs to the rule they trigger.
var dangerousVerbs = map[string]string{
	"*":           RuleWildcardVerbs,
	"escalate":    RuleEscalateVerb,
	"impersonate": RuleImpersonateVerb,
	"bind":        RuleBindVerb,
}

// dangerousResources maps resource names to the rule they trigger.
var dangerousResources = map[string]string{
	"*":                   RuleWildcardResources,
	"secrets":             RuleSecretsAccess,
	"pods/exec":           RulePodsExecAttach,
	"pods/attach":         RulePodsExecAttach,
	"nodes":               RuleNodesAccess,
	"persistentvolumes":   RulePVAccess,
	"clusterroles":        RuleRBACModification,
	"clusterrolebindings": RuleRBACModification,
}

// coreGroupResources are resources that should only trigger when apiGroups
// contains "" (core group) or "*".
var coreGroupResources = map[string]bool{
	"secrets":           true,
	"pods/exec":         true,
	"pods/attach":       true,
	"nodes":             true,
	"persistentvolumes": true,
}

// rbacGroupResources are resources that should only trigger when apiGroups
// contains "rbac.authorization.k8s.io" or "*".
var rbacGroupResources = map[string]bool{
	"clusterroles":        true,
	"clusterrolebindings": true,
	"roles":               true,
	"rolebindings":        true,
}

// escalationBindingResources triggers KC-011 when combined with create/patch/update.
var escalationBindingResources = map[string]bool{
	"roles":               true,
	"clusterroles":        true,
	"rolebindings":        true,
	"clusterrolebindings": true,
}

// escalationWorkloadResources triggers KC-012 when combined with create.
// Finding 10: expanded to include workload controllers.
var escalationWorkloadResources = map[string]bool{
	"pods":         true,
	"deployments":  true,
	"daemonsets":   true,
	"statefulsets": true,
	"jobs":         true,
	"cronjobs":     true,
	"replicasets":  true,
}

// escalationMutationVerbs are verbs that count as creating/modifying.
var escalationMutationVerbs = map[string]bool{
	"create": true,
	"patch":  true,
	"update": true,
}

// ruleDescriptions provides the title for each rule ID.
var ruleDescriptions = map[string]string{
	RuleWildcardResources:     "Wildcard resource access",
	RuleWildcardVerbs:         "Wildcard verb access",
	RuleEscalateVerb:          "Escalate verb permission",
	RuleImpersonateVerb:       "Impersonate verb permission",
	RuleBindVerb:              "Bind verb permission",
	RuleSecretsAccess:         "Secrets access",
	RulePodsExecAttach:        "Pod exec/attach access",
	RuleNodesAccess:           "Node-level access",
	RulePVAccess:              "PersistentVolume access",
	RuleRBACModification:      "RBAC modification capability",
	RuleEscalationBindings:    "Privilege escalation via role/binding modification",
	RuleEscalationPodCreation: "Privilege escalation via workload creation",
	RuleClusterAdminPod:       "Pod running with cluster-admin privileges",
	RuleRoleBindingClusterRef: "RoleBinding referencing ClusterRole",
	RuleAggregatedClusterRole: "Aggregated ClusterRole detected",
}

// ruleRemediations provides remediation guidance for each rule.
var ruleRemediations = map[string]string{
	RuleWildcardResources:     "Replace wildcard (*) resources with explicit resource names",
	RuleWildcardVerbs:         "Replace wildcard (*) verbs with specific verbs needed",
	RuleEscalateVerb:          "Remove the 'escalate' verb unless absolutely required for RBAC management",
	RuleImpersonateVerb:       "Remove the 'impersonate' verb unless required for proxy or delegation",
	RuleBindVerb:              "Remove the 'bind' verb unless required for RBAC management",
	RuleSecretsAccess:         "Restrict secrets access to specific namespaces and only the verbs needed",
	RulePodsExecAttach:        "Restrict exec/attach to specific namespaces and add audit logging",
	RuleNodesAccess:           "Limit node access to monitoring verbs (get, list, watch)",
	RulePVAccess:              "Limit PV access to read-only verbs unless storage management is required",
	RuleRBACModification:      "Limit RBAC modification to dedicated admin roles with proper audit",
	RuleEscalationBindings:    "Restrict ability to create/modify roles and bindings to admin users only",
	RuleEscalationPodCreation: "Restrict workload creation to CI/CD pipelines and use PodSecurity admission",
	RuleClusterAdminPod:       "Never use cluster-admin for pod service accounts; create a scoped role",
	RuleRoleBindingClusterRef: "Use a Role instead of ClusterRole when granting namespace-scoped access",
	RuleAggregatedClusterRole: "Review aggregation labels to ensure only intended roles are included",
}

// computeSeverity determines severity based on binding scope and whether wildcards are involved.
func computeSeverity(scope *models.BindingScope, hasWildcards bool) models.Severity {
	if scope.Unbound {
		return models.SeverityInfo
	}

	if scope.ClusterWide {
		if hasWildcards {
			return models.SeverityCritical
		}
		return models.SeverityHigh
	}

	if scope.NamespaceScoped {
		if hasWildcards {
			return models.SeverityHigh
		}
		return models.SeverityWarning
	}

	// Fallback: unbound
	return models.SeverityInfo
}

// apiGroupMatchesResource returns true if the apiGroups in the rule are
// appropriate for the given resource. This prevents false positives from
// CRDs that happen to share names with core/RBAC resources.
func apiGroupMatchesResource(apiGroups []string, resource string) bool {
	// Wildcard resources match any group
	if resource == "*" {
		return true
	}

	for _, group := range apiGroups {
		if group == "*" {
			return true
		}
		if coreGroupResources[resource] && group == "" {
			return true
		}
		if rbacGroupResources[resource] && group == "rbac.authorization.k8s.io" {
			return true
		}
	}

	return false
}

// apiGroupMatchesEscalationBinding checks if apiGroups are appropriate for
// RBAC escalation binding resources.
func apiGroupMatchesEscalationBinding(apiGroups []string) bool {
	for _, group := range apiGroups {
		if group == "*" || group == "rbac.authorization.k8s.io" {
			return true
		}
	}
	return false
}

// apiGroupMatchesEscalationWorkload checks if apiGroups are appropriate for
// workload creation escalation resources.
func apiGroupMatchesEscalationWorkload(apiGroups []string, resource string) bool {
	if resource == "*" {
		return true
	}
	for _, group := range apiGroups {
		if group == "*" {
			return true
		}
		// pods are in the core group
		if resource == "pods" && group == "" {
			return true
		}
		// workload controllers are in apps/batch groups
		if (resource == "deployments" || resource == "daemonsets" || resource == "statefulsets" || resource == "replicasets") && (group == "apps") {
			return true
		}
		if (resource == "jobs" || resource == "cronjobs") && (group == "batch") {
			return true
		}
	}
	return false
}

// hasWildcardAPIGroup returns true if apiGroups contains "*".
func hasWildcardAPIGroup(apiGroups []string) bool {
	for _, g := range apiGroups {
		if g == "*" {
			return true
		}
	}
	return false
}
