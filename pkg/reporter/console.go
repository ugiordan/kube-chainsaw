package reporter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

// ConsoleReporter outputs findings in a human-readable text format,
// grouped by severity (CRITICAL first, INFO last).
type ConsoleReporter struct{}

func (c *ConsoleReporter) Render(findings []models.Finding) (string, error) {
	if len(findings) == 0 {
		return "No findings.\n", nil
	}

	// Group findings by severity
	groups := map[models.Severity][]models.Finding{}
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}

	// Severity order: CRITICAL, HIGH, WARNING, INFO
	severityOrder := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityWarning,
		models.SeverityInfo,
	}

	var b strings.Builder

	for _, sev := range severityOrder {
		group, ok := groups[sev]
		if !ok || len(group) == 0 {
			continue
		}

		// Sort within group by RuleID for deterministic output
		sort.Slice(group, func(i, j int) bool {
			return group[i].RuleID < group[j].RuleID
		})

		fmt.Fprintf(&b, "=== %s ===\n", sev.String())

		for _, f := range group {
			resource := f.ResourceKind + "/" + f.ResourceName
			if f.ResourceNamespace != "" {
				resource = f.ResourceNamespace + "/" + resource
			}

			suppressed := ""
			if f.Suppressed {
				suppressed = " [SUPPRESSED]"
			}

			fmt.Fprintf(&b, "\n  [%s] %s%s\n", f.RuleID, f.Title, suppressed)
			fmt.Fprintf(&b, "    File:        %s\n", f.File)
			fmt.Fprintf(&b, "    Resource:    %s\n", resource)
			if f.Description != "" {
				fmt.Fprintf(&b, "    Description: %s\n", f.Description)
			}
			if f.Remediation != "" {
				fmt.Fprintf(&b, "    Remediation: %s\n", f.Remediation)
			}
		}

		b.WriteString("\n")
	}

	// Totals
	total := len(findings)
	suppressed := 0
	counts := map[models.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
		if f.Suppressed {
			suppressed++
		}
	}

	fmt.Fprintf(&b, "Total: %d findings", total)
	if suppressed > 0 {
		fmt.Fprintf(&b, " (%d suppressed)", suppressed)
	}

	parts := []string{}
	for _, sev := range severityOrder {
		if c := counts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev.String()))
		}
	}
	if len(parts) > 0 {
		b.WriteString(" [" + strings.Join(parts, ", ") + "]")
	}
	b.WriteString("\n")

	return b.String(), nil
}
