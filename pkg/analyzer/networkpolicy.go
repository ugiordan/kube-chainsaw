package analyzer

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

// analyzeNetworkPolicies checks each policy for peers that are broader than
// the policy usually needs. It intentionally does not try to calculate
// effective connectivity across multiple additive policies.
func analyzeNetworkPolicies(resources *models.LoadedResources) []models.Finding {
	keys := make([]string, 0, len(resources.NetworkPolicies))
	for key := range resources.NetworkPolicies {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var findings []models.Finding
	for _, key := range keys {
		policy := resources.NetworkPolicies[key]
		if policy == nil {
			continue
		}

		spec, ok := asStringMap(policy.Doc["spec"])
		if !ok {
			continue
		}

		target := networkPolicyTarget(spec)
		severity := networkPolicySeverity(spec)

		if networkPolicyDirectionEnabled(spec, "Ingress") {
			reasons := broadNetworkPolicyPeers(spec["ingress"], "from", "sources")
			if len(reasons) > 0 {
				f := newFinding(RuleNetworkPolicyIngress, severity, policy.File, "NetworkPolicy", policy.Name, policy.Namespace)
				f.Description = fmt.Sprintf("NetworkPolicy %q allows ingress from broad peers to %s: %s", policy.Name, target, strings.Join(reasons, "; "))
				findings = appendIfNew(findings, f)
			}
		}

		if networkPolicyDirectionEnabled(spec, "Egress") {
			reasons := broadNetworkPolicyPeers(spec["egress"], "to", "destinations")
			if len(reasons) > 0 {
				f := newFinding(RuleNetworkPolicyEgress, severity, policy.File, "NetworkPolicy", policy.Name, policy.Namespace)
				f.Description = fmt.Sprintf("NetworkPolicy %q allows egress to broad peers from %s: %s", policy.Name, target, strings.Join(reasons, "; "))
				findings = appendIfNew(findings, f)
			}
		}
	}

	return findings
}

func networkPolicyDirectionEnabled(spec map[string]interface{}, direction string) bool {
	policyTypes := toStringSlice(spec["policyTypes"])
	if len(policyTypes) > 0 {
		return contains(policyTypes, direction)
	}

	// Kubernetes defaults every policy to Ingress and adds Egress when the
	// policy has at least one egress rule.
	if direction == "Ingress" {
		return true
	}
	if direction == "Egress" {
		rules, ok := asInterfaceSlice(spec["egress"])
		return ok && len(rules) > 0
	}
	return false
}

func broadNetworkPolicyPeers(rawRules interface{}, peerKey, subject string) []string {
	rules, ok := asInterfaceSlice(rawRules)
	if !ok {
		return nil
	}

	var reasons []string
	for _, rawRule := range rules {
		rule, ok := asStringMap(rawRule)
		if !ok {
			continue
		}

		rawPeers, exists := rule[peerKey]
		if !exists || rawPeers == nil {
			reasons = appendUnique(reasons, "the rule omits a peer selector and matches all "+subject)
			continue
		}

		peers, ok := asInterfaceSlice(rawPeers)
		if !ok {
			continue
		}
		if len(peers) == 0 {
			reasons = appendUnique(reasons, "the rule has an empty peer list and matches all "+subject)
			continue
		}

		for _, rawPeer := range peers {
			peer, ok := asStringMap(rawPeer)
			if !ok {
				continue
			}
			if len(peer) == 0 {
				reasons = appendUnique(reasons, "a peer has no selector and matches all "+subject)
				continue
			}

			if selector, ok := asStringMap(peer["namespaceSelector"]); ok && selectorSelectsAll(selector) {
				reasons = appendUnique(reasons, "a namespaceSelector matches pods in all namespaces")
			}

			if ipBlock, ok := asStringMap(peer["ipBlock"]); ok && ipBlockMatchesAllIPs(ipBlock) {
				reasons = appendUnique(reasons, "an ipBlock matches all IP addresses")
			}
		}
	}

	return reasons
}

func networkPolicyTarget(spec map[string]interface{}) string {
	rawSelector, exists := spec["podSelector"]
	if !exists || rawSelector == nil {
		return "all pods in its namespace"
	}

	selector, ok := asStringMap(rawSelector)
	if ok && selectorSelectsAll(selector) {
		return "all pods in its namespace"
	}
	return "the selected pods"
}

func networkPolicySeverity(spec map[string]interface{}) models.Severity {
	rawSelector, exists := spec["podSelector"]
	if !exists || rawSelector == nil {
		return models.SeverityHigh
	}

	selector, ok := asStringMap(rawSelector)
	if ok && selectorSelectsAll(selector) {
		return models.SeverityHigh
	}
	return models.SeverityWarning
}

func selectorSelectsAll(selector map[string]interface{}) bool {
	if len(selector) == 0 {
		return true
	}

	for key, rawValue := range selector {
		switch key {
		case "matchLabels":
			labels, ok := asStringMap(rawValue)
			if !ok {
				if rawValue == nil {
					continue
				}
				return false
			}
			if len(labels) > 0 {
				return false
			}
		case "matchExpressions":
			expressions, ok := asInterfaceSlice(rawValue)
			if !ok {
				if rawValue == nil {
					continue
				}
				return false
			}
			if len(expressions) > 0 {
				return false
			}
		default:
			return false
		}
	}

	return true
}

func ipBlockMatchesAllIPs(ipBlock map[string]interface{}) bool {
	cidr, ok := ipBlock["cidr"].(string)
	if !ok {
		return false
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || prefix.Bits() != 0 {
		return false
	}

	except, exists := ipBlock["except"]
	if !exists || except == nil {
		return true
	}
	values, ok := asInterfaceSlice(except)
	return ok && len(values) == 0
}

func asStringMap(value interface{}) (map[string]interface{}, bool) {
	if value == nil {
		return nil, false
	}
	result, ok := value.(map[string]interface{})
	return result, ok
}

func asInterfaceSlice(value interface{}) ([]interface{}, bool) {
	switch values := value.(type) {
	case []interface{}:
		return values, true
	case []string:
		result := make([]interface{}, len(values))
		for i, value := range values {
			result[i] = value
		}
		return result, true
	case []map[string]interface{}:
		result := make([]interface{}, len(values))
		for i, value := range values {
			result[i] = value
		}
		return result, true
	default:
		return nil, false
	}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
