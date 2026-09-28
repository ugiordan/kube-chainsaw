package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

func analyzeSecurityContextConstraints(resources *models.LoadedResources) []models.Finding {
	keys := make([]string, 0, len(resources.SecurityContextConstraints))
	for key := range resources.SecurityContextConstraints {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var findings []models.Finding
	for _, key := range keys {
		scc := resources.SecurityContextConstraints[key]
		if scc == nil {
			continue
		}

		restrictions := permissiveSCCSettings(scc.Doc)
		if len(restrictions) == 0 {
			continue
		}

		subjects, broad := sccSubjects(scc.Doc)
		if len(subjects) == 0 {
			continue
		}

		severity := models.SeverityWarning
		if broad {
			severity = models.SeverityHigh
		}
		f := newFinding(RulePermissiveSCC, severity, scc.File, "SecurityContextConstraints", scc.Name, "")
		f.Description = fmt.Sprintf("SecurityContextConstraints %q grants permissive settings (%s) to %s", scc.Name, strings.Join(restrictions, ", "), strings.Join(subjects, ", "))
		findings = appendIfNew(findings, f)
	}

	return findings
}

func permissiveSCCSettings(doc map[string]interface{}) []string {
	var settings []string
	for field, label := range map[string]string{
		"allowPrivilegedContainer": "privileged containers",
		"allowHostNetwork":         "host network",
		"allowHostPID":             "host PID",
		"allowHostIPC":             "host IPC",
		"allowHostPorts":           "host ports",
		"allowHostDirVolumePlugin": "host directory volumes",
	} {
		if value, ok := doc[field].(bool); ok && value {
			settings = append(settings, label)
		}
	}
	allowPrivilegeEscalation, allowSet := doc["allowPrivilegeEscalation"].(bool)
	defaultAllowPrivilegeEscalation, defaultSet := doc["defaultAllowPrivilegeEscalation"].(bool)
	if (allowSet && allowPrivilegeEscalation) ||
		(defaultSet && defaultAllowPrivilegeEscalation) ||
		(!allowSet && (!defaultSet || defaultAllowPrivilegeEscalation)) {
		settings = append(settings, "privilege escalation")
	}

	if contains(stringValues(doc["allowedCapabilities"]), "*") {
		settings = append(settings, "all capabilities")
	}
	for field, label := range map[string]string{
		"allowedCapabilities":    "allowed capability",
		"defaultAddCapabilities": "default capability",
	} {
		for _, rawCapability := range stringValues(doc[field]) {
			capability := strings.TrimPrefix(strings.ToUpper(rawCapability), "CAP_")
			if capability == "*" || !dangerousCapabilities[capability] {
				continue
			}
			settings = append(settings, fmt.Sprintf("%s %s", label, capability))
		}
	}
	if contains(stringValues(doc["volumes"]), "*") {
		settings = append(settings, "all volume types")
	}
	if contains(stringValues(doc["allowedUnsafeSysctls"]), "*") {
		settings = append(settings, "all unsafe sysctls")
	}
	if contains(stringValues(doc["seccompProfiles"]), "*") {
		settings = append(settings, "all seccomp profiles")
	}

	for field, label := range map[string]string{
		"runAsUser":          "arbitrary user IDs",
		"seLinuxContext":     "arbitrary SELinux contexts",
		"fsGroup":            "arbitrary FS groups",
		"supplementalGroups": "arbitrary supplemental groups",
	} {
		strategy, ok := asStringMap(doc[field])
		if ok && strategy["type"] == "RunAsAny" {
			settings = append(settings, label)
		}
	}

	sort.Strings(settings)
	return settings
}

func sccSubjects(doc map[string]interface{}) ([]string, bool) {
	var subjects []string
	broad := false
	for _, item := range stringValues(doc["users"]) {
		subjects = appendUnique(subjects, "user "+item)
	}
	for _, item := range stringValues(doc["groups"]) {
		subjects = appendUnique(subjects, "group "+item)
		broad = broad || broadSCCGroup(item)
	}
	sort.Strings(subjects)
	return subjects, broad
}

func broadSCCGroup(subject string) bool {
	return subject == "*" ||
		subject == "system:authenticated" ||
		subject == "system:unauthenticated" ||
		subject == "system:serviceaccounts" ||
		strings.HasPrefix(subject, "system:serviceaccounts:")
}
