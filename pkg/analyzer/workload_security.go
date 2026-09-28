package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

var dangerousCapabilities = map[string]bool{
	"ALL":             true,
	"DAC_READ_SEARCH": true,
	"BPF":             true,
	"MAC_ADMIN":       true,
	"NET_ADMIN":       true,
	"NET_RAW":         true,
	"PERFMON":         true,
	"SYS_ADMIN":       true,
	"SYS_CHROOT":      true,
	"SYS_MODULE":      true,
	"SYS_PTRACE":      true,
	"SYS_RAWIO":       true,
}

var highRiskCapabilities = map[string]bool{
	"ALL":             true,
	"DAC_READ_SEARCH": true,
	"BPF":             true,
	"MAC_ADMIN":       true,
	"SYS_ADMIN":       true,
	"SYS_MODULE":      true,
	"SYS_PTRACE":      true,
	"SYS_RAWIO":       true,
}

func analyzeWorkloadSecurity(resources *models.LoadedResources) []models.Finding {
	var findings []models.Finding

	podKeys := make([]string, 0, len(resources.Pods))
	for key := range resources.Pods {
		podKeys = append(podKeys, key)
	}
	sort.Strings(podKeys)
	for _, key := range podKeys {
		pod := resources.Pods[key]
		if pod == nil {
			continue
		}
		findings = append(findings, analyzeWorkloadSecurityObject(pod.Doc, "Pod", pod.Name, pod.Namespace, pod.File)...)
	}

	workloadKeys := make([]string, 0, len(resources.Workloads))
	for key := range resources.Workloads {
		workloadKeys = append(workloadKeys, key)
	}
	sort.Strings(workloadKeys)
	for _, key := range workloadKeys {
		workload := resources.Workloads[key]
		if workload == nil {
			continue
		}
		findings = append(findings, analyzeWorkloadSecurityObject(workload.Doc, workload.Kind, workload.Name, workload.Namespace, workload.File)...)
	}

	return findings
}

func analyzeWorkloadSecurityObject(doc map[string]interface{}, kind, name, namespace, file string) []models.Finding {
	podSpec := extractPodSpec(doc, kind)
	if podSpec == nil {
		return nil
	}

	var privilegedContainers []string
	var capabilityDetails []string
	var hostPathDetails []string
	mountedVolumes := make(map[string]bool)
	severityByRule := map[string]models.Severity{}

	for _, containerField := range []string{"containers", "initContainers", "ephemeralContainers"} {
		containers, ok := asInterfaceSlice(podSpec[containerField])
		if !ok {
			continue
		}
		for _, rawContainer := range containers {
			container, ok := asStringMap(rawContainer)
			if !ok {
				continue
			}
			containerName, _ := container["name"].(string)
			if containerName == "" {
				containerName = "<unnamed>"
			}
			for _, volumeField := range []string{"volumeMounts", "volumeDevices"} {
				volumeMounts, ok := asInterfaceSlice(container[volumeField])
				if !ok {
					continue
				}
				for _, rawVolumeMount := range volumeMounts {
					volumeMount, ok := asStringMap(rawVolumeMount)
					if !ok {
						continue
					}
					volumeName, _ := volumeMount["name"].(string)
					if volumeName != "" {
						mountedVolumes[volumeName] = true
					}
				}
			}

			securityContext, _ := asStringMap(container["securityContext"])
			if boolValue(securityContext["privileged"]) {
				privilegedContainers = appendUnique(privilegedContainers, containerName)
				severityByRule[RulePrivilegedContainer] = models.SeverityHigh
			}

			capabilities, ok := asStringMap(securityContext["capabilities"])
			if !ok {
				continue
			}
			for _, rawCapability := range stringValues(capabilities["add"]) {
				capability := strings.TrimPrefix(strings.ToUpper(rawCapability), "CAP_")
				if !dangerousCapabilities[capability] {
					continue
				}
				capabilityDetails = appendUnique(capabilityDetails, fmt.Sprintf("%s (%s)", containerName, capability))
				if highRiskCapabilities[capability] {
					severityByRule[RuleDangerousCapabilities] = models.SeverityHigh
				} else if severityByRule[RuleDangerousCapabilities] < models.SeverityWarning {
					severityByRule[RuleDangerousCapabilities] = models.SeverityWarning
				}
			}
		}
	}

	var hostNamespaces []string
	for _, field := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if boolValue(podSpec[field]) {
			hostNamespaces = append(hostNamespaces, field)
		}
	}
	if len(hostNamespaces) > 0 {
		severityByRule[RuleHostNamespace] = models.SeverityHigh
	}

	if volumes, ok := asInterfaceSlice(podSpec["volumes"]); ok {
		for _, rawVolume := range volumes {
			volume, ok := asStringMap(rawVolume)
			if !ok {
				continue
			}
			hostPath, ok := asStringMap(volume["hostPath"])
			if !ok {
				continue
			}
			volumeName, _ := volume["name"].(string)
			if !mountedVolumes[volumeName] {
				continue
			}
			path, _ := hostPath["path"].(string)
			if path == "" {
				path = "<unspecified>"
			}
			hostPathDetails = appendUnique(hostPathDetails, fmt.Sprintf("%s (%s)", volumeName, path))
			if sensitiveHostPath(path) {
				severityByRule[RuleHostPath] = models.SeverityHigh
			} else if severityByRule[RuleHostPath] < models.SeverityWarning {
				severityByRule[RuleHostPath] = models.SeverityWarning
			}
		}
	}

	var findings []models.Finding
	if len(privilegedContainers) > 0 {
		f := newFinding(RulePrivilegedContainer, severityByRule[RulePrivilegedContainer], file, kind, name, namespace)
		f.Description = fmt.Sprintf("%s %q requests privileged containers: %s", kind, name, strings.Join(privilegedContainers, ", "))
		findings = appendIfNew(findings, f)
	}
	if len(hostNamespaces) > 0 {
		f := newFinding(RuleHostNamespace, severityByRule[RuleHostNamespace], file, kind, name, namespace)
		f.Description = fmt.Sprintf("%s %q requests host namespace access: %s", kind, name, strings.Join(hostNamespaces, ", "))
		findings = appendIfNew(findings, f)
	}
	if len(hostPathDetails) > 0 {
		f := newFinding(RuleHostPath, severityByRule[RuleHostPath], file, kind, name, namespace)
		f.Description = fmt.Sprintf("%s %q mounts hostPath volumes: %s", kind, name, strings.Join(hostPathDetails, ", "))
		findings = appendIfNew(findings, f)
	}
	if len(capabilityDetails) > 0 {
		f := newFinding(RuleDangerousCapabilities, severityByRule[RuleDangerousCapabilities], file, kind, name, namespace)
		f.Description = fmt.Sprintf("%s %q adds dangerous Linux capabilities: %s", kind, name, strings.Join(capabilityDetails, ", "))
		findings = appendIfNew(findings, f)
	}

	return findings
}

func extractPodSpec(doc map[string]interface{}, kind string) map[string]interface{} {
	spec, ok := asStringMap(doc["spec"])
	if !ok {
		return nil
	}
	if kind == "Pod" {
		return spec
	}
	if kind == "CronJob" {
		jobTemplate, ok := asStringMap(spec["jobTemplate"])
		if !ok {
			return nil
		}
		spec, ok = asStringMap(jobTemplate["spec"])
		if !ok {
			return nil
		}
	}
	template, ok := asStringMap(spec["template"])
	if !ok {
		return nil
	}
	podSpec, _ := asStringMap(template["spec"])
	return podSpec
}

func boolValue(value interface{}) bool {
	result, _ := value.(bool)
	return result
}

func stringValues(value interface{}) []string {
	return toStringSlice(value)
}

func sensitiveHostPath(path string) bool {
	if path != "/" {
		path = strings.TrimSuffix(path, "/")
	}
	if path == "/" {
		return true
	}
	for _, prefix := range []string{"/dev", "/etc", "/etc/kubernetes", "/proc", "/sys", "/var/lib/kubelet", "/var/lib/containers", "/var/run"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}
