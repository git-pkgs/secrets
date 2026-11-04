package detect

import (
	"context"

	"github.com/git-pkgs/secrets/betterleaks/report"
)

// ValidateFindings applies optional credential validation through the shared pool.
func (d *Detector) ValidateFindings(ctx context.Context, findings []report.Finding) ([]report.Finding, error) {
	if d.ValidationPool == nil {
		return findings, nil
	}
	validated := make([]report.Finding, 0, len(findings))
	for _, finding := range findings {
		program, ok, err := d.validationProgram(finding.RuleID)
		if err != nil {
			return nil, err
		}
		if ok {
			finding, err = d.ValidationPool.ValidateContext(ctx, finding, program)
			if err != nil {
				return nil, err
			}
		}
		if !d.ValidationExtractEmpty {
			finding.ValidationMeta = stripEmptyMeta(finding.ValidationMeta)
		}
		if len(d.ValidationStatusFilter) > 0 {
			status := string(finding.ValidationStatus)
			if status == "" {
				status = "none"
			}
			if _, ok := d.ValidationStatusFilter[status]; !ok {
				continue
			}
		}
		validated = append(validated, finding)
	}
	return validated, nil
}
