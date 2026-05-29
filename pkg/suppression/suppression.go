package suppression

import (
	"fmt"
	"os"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
	"sigs.k8s.io/yaml"
)

const (
	// MaxSuppressionFileSize is the maximum size of a suppressions file (1MB).
	MaxSuppressionFileSize = 1 * 1024 * 1024
)

// Suppression defines a single suppression entry.
type Suppression struct {
	RuleID            string `yaml:"rule_id" json:"rule_id"`
	ResourceName      string `yaml:"resource_name" json:"resource_name"`
	ResourceNamespace string `yaml:"resource_namespace,omitempty" json:"resource_namespace,omitempty"`
	Reason            string `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// SuppressionFile is the top-level structure of a suppressions YAML file.
type SuppressionFile struct {
	Suppressions []Suppression `yaml:"suppressions" json:"suppressions"`
}

// LoadSuppressions reads and parses a suppressions YAML file.
// Finding 13: enforces file size limit and validates entries.
func LoadSuppressions(path string) ([]Suppression, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read suppressions file %q: %w", path, err)
	}

	if info.Size() > MaxSuppressionFileSize {
		return nil, fmt.Errorf("suppressions file %q exceeds maximum size (%d > %d bytes)", path, info.Size(), MaxSuppressionFileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read suppressions file %q: %w", path, err)
	}

	var sf SuppressionFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("failed to parse suppressions file %q: %w", path, err)
	}

	// Validate entries: rule_id and resource_name must be non-empty
	for i, s := range sf.Suppressions {
		if s.RuleID == "" {
			return nil, fmt.Errorf("suppression entry %d in %q has empty rule_id", i, path)
		}
		if s.ResourceName == "" {
			return nil, fmt.Errorf("suppression entry %d (rule_id=%q) in %q has empty resource_name", i, s.RuleID, path)
		}
		// NEW-3: validate rule_id matches known pattern
		if !isValidRuleID(s.RuleID) {
			fmt.Fprintf(os.Stderr, "warning: suppression entry %d in %q has unrecognized rule_id %q (expected KC-001 through KC-015)\n", i, path, s.RuleID)
		}
	}

	return sf.Suppressions, nil
}

// isValidRuleID checks if a rule_id follows the expected pattern (KC-001 through KC-015)
func isValidRuleID(ruleID string) bool {
	// Known rule IDs: KC-001 through KC-015
	if len(ruleID) != 6 || ruleID[:3] != "KC-" {
		return false
	}
	// Extract numeric part
	numPart := ruleID[3:]
	if numPart < "001" || numPart > "015" {
		return false
	}
	return true
}

// ApplySuppressions marks findings as suppressed when they match a suppression
// entry. A match requires rule_id and resource_name to be equal. If the
// suppression specifies a resource_namespace, it must also match; if the
// namespace is empty, the suppression acts as a wildcard across all namespaces.
// The original slice is modified in place and returned.
func ApplySuppressions(findings []models.Finding, suppressions []Suppression) []models.Finding {
	for i := range findings {
		for _, s := range suppressions {
			if matches(&findings[i], &s) {
				findings[i].Suppressed = true
				break
			}
		}
	}
	return findings
}

func matches(f *models.Finding, s *Suppression) bool {
	if f.RuleID != s.RuleID {
		return false
	}
	if f.ResourceName != s.ResourceName {
		return false
	}
	// Empty suppression namespace = wildcard (matches all)
	if s.ResourceNamespace != "" && f.ResourceNamespace != s.ResourceNamespace {
		return false
	}
	return true
}
