package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

func analyzeExternalExposure(resources *models.LoadedResources) []models.Finding {
	var findings []models.Finding

	serviceKeys := sortedKeys(resources.Services)
	for _, key := range serviceKeys {
		service := resources.Services[key]
		if service == nil {
			continue
		}
		spec, ok := asStringMap(service.Doc["spec"])
		if !ok {
			continue
		}
		var reasons []string
		serviceType, _ := spec["type"].(string)
		switch serviceType {
		case "LoadBalancer":
			reasons = append(reasons, "type LoadBalancer")
		case "NodePort":
			reasons = append(reasons, "type NodePort")
		case "ExternalName":
			reasons = append(reasons, "type ExternalName")
		}
		if externalIPs := stringValues(spec["externalIPs"]); len(externalIPs) > 0 {
			reasons = append(reasons, "externalIPs configured")
		}
		if len(reasons) > 0 {
			f := newFinding(RuleExternalService, models.SeverityWarning, service.File, "Service", service.Name, service.Namespace)
			f.Description = fmt.Sprintf("Service %q declares external reachability: %s", service.Name, strings.Join(reasons, ", "))
			findings = appendIfNew(findings, f)
		}
	}

	ingressKeys := sortedKeys(resources.Ingresses)
	for _, key := range ingressKeys {
		ingress := resources.Ingresses[key]
		if ingress == nil {
			continue
		}
		spec, ok := asStringMap(ingress.Doc["spec"])
		if !ok {
			continue
		}
		rules, _ := asInterfaceSlice(spec["rules"])
		_, hasDefaultBackend := spec["defaultBackend"]
		if len(rules) == 0 && !hasDefaultBackend {
			continue
		}
		if ingressHasUnencryptedHosts(spec, rules, hasDefaultBackend) {
			f := newFinding(RuleUnencryptedRoute, models.SeverityWarning, ingress.File, "Ingress", ingress.Name, ingress.Namespace)
			f.Description = fmt.Sprintf("Ingress %q declares routes without TLS", ingress.Name)
			findings = appendIfNew(findings, f)
		}
		if ingressHasBroadHost(rules, hasDefaultBackend) {
			f := newFinding(RuleBroadExternalRoute, models.SeverityWarning, ingress.File, "Ingress", ingress.Name, ingress.Namespace)
			f.Description = fmt.Sprintf("Ingress %q declares a catch-all or wildcard host", ingress.Name)
			findings = appendIfNew(findings, f)
		}
	}

	routeKeys := sortedKeys(resources.Routes)
	for _, key := range routeKeys {
		route := resources.Routes[key]
		if route == nil {
			continue
		}
		spec, ok := asStringMap(route.Doc["spec"])
		if !ok {
			continue
		}
		termination, hasTLS := "", false
		if tls, ok := asStringMap(spec["tls"]); ok {
			termination, _ = tls["termination"].(string)
			hasTLS = termination != ""
		}
		insecurePolicy, _ := asStringMap(spec["tls"])
		insecureMode, _ := insecurePolicy["insecureEdgeTerminationPolicy"].(string)
		if insecureMode == "Allow" {
			f := newFinding(RuleUnencryptedRoute, models.SeverityHigh, route.File, "Route", route.Name, route.Namespace)
			f.Description = fmt.Sprintf("Route %q allows plaintext traffic with insecureEdgeTerminationPolicy Allow", route.Name)
			findings = appendIfNew(findings, f)
		} else if !hasTLS {
			f := newFinding(RuleUnencryptedRoute, models.SeverityWarning, route.File, "Route", route.Name, route.Namespace)
			f.Description = fmt.Sprintf("Route %q has no TLS termination", route.Name)
			findings = appendIfNew(findings, f)
		}
		wildcardPolicy, _ := spec["wildcardPolicy"].(string)
		if wildcardPolicy == "Subdomain" {
			f := newFinding(RuleBroadExternalRoute, models.SeverityWarning, route.File, "Route", route.Name, route.Namespace)
			f.Description = fmt.Sprintf("Route %q exposes a wildcard subdomain", route.Name)
			findings = appendIfNew(findings, f)
		}
	}

	return findings
}

func sortedKeys[T any](values map[string]*T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func ingressHasBroadHost(rules []interface{}, hasDefaultBackend bool) bool {
	if len(rules) == 0 {
		return hasDefaultBackend
	}
	for _, rawRule := range rules {
		rule, ok := asStringMap(rawRule)
		if !ok {
			continue
		}
		host, _ := rule["host"].(string)
		if host == "" || strings.HasPrefix(host, "*.") {
			return true
		}
	}
	return false
}

func ingressHasUnencryptedHosts(spec map[string]interface{}, rules []interface{}, hasDefaultBackend bool) bool {
	tlsEntries, ok := asInterfaceSlice(spec["tls"])
	if !ok || len(tlsEntries) == 0 {
		return true
	}

	var tlsHosts []string
	for _, rawTLS := range tlsEntries {
		tlsEntry, ok := asStringMap(rawTLS)
		if !ok {
			continue
		}
		hosts, ok := tlsEntry["hosts"]
		if !ok {
			return false
		}
		values := stringValues(hosts)
		if len(values) == 0 {
			return false
		}
		tlsHosts = append(tlsHosts, values...)
	}

	if len(rules) == 0 {
		return hasDefaultBackend
	}
	for _, rawRule := range rules {
		rule, ok := asStringMap(rawRule)
		if !ok {
			return true
		}
		host, _ := rule["host"].(string)
		if host == "" || !ingressHostCovered(host, tlsHosts) {
			return true
		}
	}
	return false
}

func ingressHostCovered(host string, tlsHosts []string) bool {
	for _, tlsHost := range tlsHosts {
		if tlsHost == host {
			return true
		}
		if strings.HasPrefix(tlsHost, "*.") && strings.HasSuffix(host, tlsHost[1:]) {
			return true
		}
	}
	return false
}
