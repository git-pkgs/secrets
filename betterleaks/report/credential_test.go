package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialReportRedactsOverlappingSecretsAndMetadataKeys(t *testing.T) {
	got := NewCredentialReport(Finding{
		RuleID:           "test",
		ValidationStatus: ValidationStatusValid,
		Attributes: map[string]string{
			"credential-abcdef": "abcdef abc",
		},
		ValidationMeta: map[string]any{
			"credential-abcdef": "abcdef abc",
		},
	}, []string{"abc", "abcdef"}, false)

	value, ok := got.Validation.Metadata["credential-[redacted]"]
	if !ok {
		t.Fatalf("sanitized metadata keys = %#v", got.Validation.Metadata)
	}
	if value != "[redacted] [redacted]" {
		t.Fatalf("sanitized metadata value = %#v", value)
	}
	if got.Attributes["credential-[redacted]"] != "[redacted] [redacted]" {
		t.Fatalf("sanitized attributes = %#v", got.Attributes)
	}
}

func TestCredentialReportUsesComponentSchema(t *testing.T) {
	result := NewCredentialReport(Finding{
		RuleID:           "test-rule",
		ValidationStatus: ValidationStatusValid,
		ComponentSets: []ComponentSet{{
			ValidationStatus: ValidationStatusValid,
			Components: []*ComponentFinding{
				{RuleID: "required-component"},
				{RuleID: "optional-component", Optional: true},
			},
		}},
	}, nil, false)

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	encoded := string(data)
	if !strings.Contains(encoded, `"component_sets"`) || !strings.Contains(encoded, `"optional":true`) {
		t.Fatalf("component schema missing from %s", encoded)
	}
	if strings.Contains(encoded, "required_sets") || strings.Contains(encoded, "required_components") {
		t.Fatalf("legacy required schema present in %s", encoded)
	}
}
