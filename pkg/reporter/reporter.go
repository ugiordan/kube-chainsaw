package reporter

import "github.com/ugiordan/kube-chainsaw/pkg/models"

// Reporter renders a slice of findings into a formatted string.
type Reporter interface {
	Render(findings []models.Finding) (string, error)
}
