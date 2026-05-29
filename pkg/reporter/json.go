package reporter

import (
	"encoding/json"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

// JSONReporter outputs findings as a JSON document.
type JSONReporter struct{}

type jsonFinding struct {
	RuleID            string `json:"rule_id"`
	Severity          string `json:"severity"`
	Title             string `json:"title"`
	File              string `json:"file"`
	Description       string `json:"description"`
	Remediation       string `json:"remediation"`
	ResourceKind      string `json:"resource_kind"`
	ResourceName      string `json:"resource_name"`
	ResourceNamespace string `json:"resource_namespace"`
	Fingerprint       string `json:"fingerprint"`
	Suppressed        bool   `json:"suppressed"`
}

type jsonReport struct {
	Findings []jsonFinding `json:"findings"`
}

func (j *JSONReporter) Render(findings []models.Finding) (string, error) {
	report := jsonReport{
		Findings: make([]jsonFinding, len(findings)),
	}

	for i, f := range findings {
		report.Findings[i] = jsonFinding{
			RuleID:            f.RuleID,
			Severity:          f.Severity.String(),
			Title:             f.Title,
			File:              f.File,
			Description:       f.Description,
			Remediation:       f.Remediation,
			ResourceKind:      f.ResourceKind,
			ResourceName:      f.ResourceName,
			ResourceNamespace: f.ResourceNamespace,
			Fingerprint:       f.Fingerprint,
			Suppressed:        f.Suppressed,
		}
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}
