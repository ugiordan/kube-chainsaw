package analyzer

import (
	"fmt"
	"strings"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

// Analyze examines loaded RBAC resources and returns security findings.
func Analyze(resources *models.LoadedResources) []models.Finding {
	if resources == nil || resources.IsEmpty() {
		return nil
	}

	var findings []models.Finding

	// Phase 1: Analyze ClusterRoles
	for name, cr := range resources.ClusterRoles {
		scope := resolveClusterRoleScope(name, resources)

		// Check for aggregated ClusterRole (KC-015)
		if isAggregated(cr.Doc) {
			f := newFinding(RuleAggregatedClusterRole, models.SeverityInfo, cr.File, "ClusterRole", name, "")
			findings = appendIfNew(findings, f)
		}

		// Check rules for dangerous patterns
		findings = append(findings, checkRules(cr.Rules, name, "ClusterRole", "", cr.File, &scope, false)...)
	}

	// Phase 2: Analyze Roles (namespace-scoped, severity capped at WARNING)
	for key, role := range resources.Roles {
		scope := resolveRoleScope(key, resources)
		findings = append(findings, checkRules(role.Rules, extractNameFromKey(key), "Role", role.Namespace, role.File, &scope, true)...)
	}

	// Phase 3: Privilege chain analysis
	findings = append(findings, analyzePrivilegeChains(resources)...)

	return findings
}

// checkRules inspects the rules of a role (ClusterRole or Role) for dangerous patterns.
func checkRules(rules []map[string]interface{}, roleName, roleKind, namespace, file string, scope *models.BindingScope, isNamespaced bool) []models.Finding {
	var findings []models.Finding
	seen := make(map[string]bool) // deduplicate: rule_id per resource

	for _, rule := range rules {
		verbs := toStringSlice(rule["verbs"])
		resources := toStringSlice(rule["resources"])

		hasWildcardVerb := contains(verbs, "*")
		hasWildcardResource := contains(resources, "*")
		hasWildcards := hasWildcardVerb || hasWildcardResource

		// Check dangerous verbs
		for _, verb := range verbs {
			if ruleID, ok := dangerousVerbs[verb]; ok {
				dedup := ruleID + "|" + roleName
				if !seen[dedup] {
					seen[dedup] = true
					sev := computeSeverity(scope, hasWildcards)
					if isNamespaced {
						sev = capSeverity(sev, models.SeverityWarning)
					}
					f := newFinding(ruleID, sev, file, roleKind, roleName, namespace)
					f.Description = fmt.Sprintf("Role %q has dangerous verb %q", roleName, verb)
					findings = append(findings, f)
				}
			}
		}

		// Check dangerous resources
		for _, res := range resources {
			if ruleID, ok := dangerousResources[res]; ok {
				dedup := ruleID + "|" + roleName
				if !seen[dedup] {
					seen[dedup] = true
					sev := computeSeverity(scope, hasWildcards)
					if isNamespaced {
						sev = capSeverity(sev, models.SeverityWarning)
					}
					f := newFinding(ruleID, sev, file, roleKind, roleName, namespace)
					f.Description = fmt.Sprintf("Role %q grants access to dangerous resource %q", roleName, res)
					findings = append(findings, f)
				}
			}
		}

		// Check escalation combos: KC-011 (create/patch/update on roles/bindings)
		if hasEscalationBindingCombo(verbs, resources) {
			dedup := RuleEscalationBindings + "|" + roleName
			if !seen[dedup] {
				seen[dedup] = true
				sev := computeSeverity(scope, hasWildcards)
				if isNamespaced {
					sev = capSeverity(sev, models.SeverityWarning)
				}
				f := newFinding(RuleEscalationBindings, sev, file, roleKind, roleName, namespace)
				f.Description = fmt.Sprintf("Role %q can create/modify roles or bindings (privilege escalation risk)", roleName)
				findings = append(findings, f)
			}
		}

		// Check escalation combo: KC-012 (create on pods/workloads)
		if hasEscalationPodCombo(verbs, resources) {
			dedup := RuleEscalationPodCreation + "|" + roleName
			if !seen[dedup] {
				seen[dedup] = true
				sev := computeSeverity(scope, hasWildcards)
				if isNamespaced {
					sev = capSeverity(sev, models.SeverityWarning)
				}
				f := newFinding(RuleEscalationPodCreation, sev, file, roleKind, roleName, namespace)
				f.Description = fmt.Sprintf("Role %q can create pods/workloads (privilege escalation risk)", roleName)
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// hasEscalationBindingCombo returns true if verbs include create/patch/update AND
// resources include roles, clusterroles, rolebindings, or clusterrolebindings.
func hasEscalationBindingCombo(verbs, resources []string) bool {
	hasMutationVerb := false
	for _, v := range verbs {
		if escalationMutationVerbs[v] || v == "*" {
			hasMutationVerb = true
			break
		}
	}
	if !hasMutationVerb {
		return false
	}

	for _, r := range resources {
		if escalationBindingResources[r] || r == "*" {
			return true
		}
	}
	return false
}

// hasEscalationPodCombo returns true if verbs include "create" (or "*") AND
// resources include pods or workload controllers.
func hasEscalationPodCombo(verbs, resources []string) bool {
	hasCreate := false
	for _, v := range verbs {
		if v == "create" || v == "*" {
			hasCreate = true
			break
		}
	}
	if !hasCreate {
		return false
	}

	for _, r := range resources {
		if escalationPodResources[r] || r == "*" {
			return true
		}
	}
	return false
}

// analyzePrivilegeChains walks Pod -> SA -> Binding -> Role chains.
func analyzePrivilegeChains(resources *models.LoadedResources) []models.Finding {
	var findings []models.Finding

	for _, pod := range resources.Pods {
		saKey := pod.Namespace + "/" + pod.ServiceAccountName

		// Check ClusterRoleBindings referencing this SA
		for _, crb := range resources.ClusterRoleBindings {
			if !bindingReferencesSubject(crb, pod.ServiceAccountName, pod.Namespace) {
				continue
			}

			roleRefName := getRoleRefName(crb.RoleRef)
			roleRefKind := getRoleRefKind(crb.RoleRef)

			if roleRefKind == "ClusterRole" && roleRefName == "cluster-admin" {
				// KC-013: Pod running with cluster-admin
				f := newFinding(RuleClusterAdminPod, models.SeverityCritical, pod.File, "Pod", pod.Name, pod.Namespace)
				f.Description = fmt.Sprintf(
					"Pod %q uses ServiceAccount %q which is bound to cluster-admin via ClusterRoleBinding %q",
					pod.Name, saKey, crb.Name,
				)
				findings = appendIfNew(findings, f)
			}
		}

		// Check RoleBindings referencing a ClusterRole (KC-014)
		for _, rb := range resources.RoleBindings {
			if !bindingReferencesSubject(rb, pod.ServiceAccountName, pod.Namespace) {
				continue
			}

			roleRefKind := getRoleRefKind(rb.RoleRef)
			if roleRefKind == "ClusterRole" {
				roleRefName := getRoleRefName(rb.RoleRef)
				f := newFinding(RuleRoleBindingClusterRef, models.SeverityWarning, rb.File, "RoleBinding", rb.Name, rb.Namespace)
				f.Description = fmt.Sprintf(
					"RoleBinding %q in namespace %q references ClusterRole %q (used by pod %q via SA %q)",
					rb.Name, rb.Namespace, roleRefName, pod.Name, saKey,
				)
				findings = appendIfNew(findings, f)
			}
		}
	}

	// Also check RoleBindings referencing ClusterRoles even without pods
	for _, rb := range resources.RoleBindings {
		roleRefKind := getRoleRefKind(rb.RoleRef)
		if roleRefKind == "ClusterRole" {
			roleRefName := getRoleRefName(rb.RoleRef)
			f := newFinding(RuleRoleBindingClusterRef, models.SeverityWarning, rb.File, "RoleBinding", rb.Name, rb.Namespace)
			f.Description = fmt.Sprintf(
				"RoleBinding %q in namespace %q references ClusterRole %q",
				rb.Name, rb.Namespace, roleRefName,
			)
			findings = appendIfNew(findings, f)
		}
	}

	return findings
}

// resolveClusterRoleScope determines how a ClusterRole is bound.
func resolveClusterRoleScope(name string, resources *models.LoadedResources) models.BindingScope {
	scope := models.BindingScope{
		SubjectTypes: make(map[string]int),
	}

	// Check ClusterRoleBindings
	for _, crb := range resources.ClusterRoleBindings {
		if getRoleRefName(crb.RoleRef) == name && getRoleRefKind(crb.RoleRef) == "ClusterRole" {
			scope.ClusterWide = true
			scope.ClusterBindings = append(scope.ClusterBindings, crb.Name)
			countSubjects(crb.Subjects, scope.SubjectTypes)
		}
	}

	// Check RoleBindings referencing this ClusterRole
	for _, rb := range resources.RoleBindings {
		if getRoleRefName(rb.RoleRef) == name && getRoleRefKind(rb.RoleRef) == "ClusterRole" {
			scope.NamespaceScoped = true
			scope.RoleBindings = append(scope.RoleBindings, rb.Name)
			countSubjects(rb.Subjects, scope.SubjectTypes)
		}
	}

	if !scope.ClusterWide && !scope.NamespaceScoped {
		scope.Unbound = true
	}

	return scope
}

// resolveRoleScope determines how a Role is bound.
func resolveRoleScope(key string, resources *models.LoadedResources) models.BindingScope {
	scope := models.BindingScope{
		SubjectTypes: make(map[string]int),
	}

	role, ok := resources.Roles[key]
	if !ok {
		scope.Unbound = true
		return scope
	}

	name := extractNameFromKey(key)

	for _, rb := range resources.RoleBindings {
		if getRoleRefName(rb.RoleRef) == name && getRoleRefKind(rb.RoleRef) == "Role" && rb.Namespace == role.Namespace {
			scope.NamespaceScoped = true
			scope.RoleBindings = append(scope.RoleBindings, rb.Name)
			countSubjects(rb.Subjects, scope.SubjectTypes)
		}
	}

	if !scope.NamespaceScoped {
		scope.Unbound = true
	}

	return scope
}

// Helper functions

func newFinding(ruleID string, severity models.Severity, file, resourceKind, resourceName, namespace string) models.Finding {
	f := models.Finding{
		RuleID:            ruleID,
		Severity:          severity,
		Title:             ruleDescriptions[ruleID],
		File:              file,
		Remediation:       ruleRemediations[ruleID],
		ResourceKind:      resourceKind,
		ResourceName:      resourceName,
		ResourceNamespace: namespace,
	}
	f.ComputeFingerprint()
	return f
}

func appendIfNew(findings []models.Finding, f models.Finding) []models.Finding {
	for _, existing := range findings {
		if existing.Fingerprint == f.Fingerprint {
			return findings
		}
	}
	return append(findings, f)
}

func capSeverity(s, max models.Severity) models.Severity {
	if s > max {
		return max
	}
	return s
}

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return val
	default:
		return nil
	}
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func isAggregated(doc map[string]interface{}) bool {
	_, ok := doc["aggregationRule"]
	return ok
}

func getRoleRefName(roleRef map[string]interface{}) string {
	if roleRef == nil {
		return ""
	}
	name, _ := roleRef["name"].(string)
	return name
}

func getRoleRefKind(roleRef map[string]interface{}) string {
	if roleRef == nil {
		return ""
	}
	kind, _ := roleRef["kind"].(string)
	return kind
}

func bindingReferencesSubject(binding *models.BindingData, saName, saNamespace string) bool {
	for _, subj := range binding.Subjects {
		kind, _ := subj["kind"].(string)
		name, _ := subj["name"].(string)
		ns, _ := subj["namespace"].(string)

		if kind == "ServiceAccount" && name == saName && ns == saNamespace {
			return true
		}
	}
	return false
}

func countSubjects(subjects []map[string]interface{}, counts map[string]int) {
	for _, subj := range subjects {
		kind, _ := subj["kind"].(string)
		if kind != "" {
			counts[kind]++
		}
	}
}

func extractNameFromKey(key string) string {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return key
}
