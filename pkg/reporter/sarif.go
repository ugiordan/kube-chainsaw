package reporter

import (
	"encoding/json"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/ugiordan/kube-chainsaw/internal/version"
	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

// SARIFReporter outputs findings in SARIF 2.1.0 format.
type SARIFReporter struct{}

func (s *SARIFReporter) Render(findings []models.Finding) (string, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return "", err
	}

	run := sarif.NewRunWithInformationURI("kube-chainsaw", "https://github.com/ugiordan/kube-chainsaw")
	run.Tool.Driver.Version = &version.Version

	// Collect unique rules
	rulesSeen := map[string]bool{}
	for _, f := range findings {
		if rulesSeen[f.RuleID] {
			continue
		}
		rulesSeen[f.RuleID] = true

		rule := run.AddRule(f.RuleID)
		rule.WithShortDescription(sarif.NewMultiformatMessageString(f.Title))
		if f.Remediation != "" {
			rule.WithHelp(sarif.NewMultiformatMessageString(f.Remediation))
		}
	}

	// Add results
	for _, f := range findings {
		level := severityToSARIFLevel(f.Severity)
		message := f.Description
		if message == "" {
			message = f.Title
		}

		result := sarif.NewRuleResult(f.RuleID)
		result.WithLevel(level)
		result.WithMessage(sarif.NewTextMessage(message))

		// Add original severity to properties bag
		props := sarif.NewPropertyBag()
		props.Add("kube-chainsaw/severity", f.Severity.String())
		result.Properties = props.Properties

		// Add location
		resource := f.ResourceKind + "/" + f.ResourceName
		if f.ResourceNamespace != "" {
			resource = f.ResourceNamespace + "/" + resource
		}

		loc := sarif.NewLocationWithPhysicalLocation(
			sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(f.File)),
		)
		loc.WithMessage(sarif.NewTextMessage(resource))
		result.WithLocations([]*sarif.Location{loc})

		// Fingerprint
		if f.Fingerprint != "" {
			result.WithPartialFingerPrints(map[string]interface{}{
				"kube-chainsaw/v1": f.Fingerprint,
			})
		}

		// Suppression
		if f.Suppressed {
			result.WithSuppression([]*sarif.Suppression{
				sarif.NewSuppression("inSource"),
			})
		}

		run.AddResult(result)
	}

	report.AddRun(run)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

func severityToSARIFLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityWarning:
		return "warning"
	case models.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}
