package report

import (
	"sort"
	"strings"
)

const CredentialReportSchemaVersion = 1

// CredentialReport keeps validation in its own namespace. Credential access
// analysis can be added later as an "analysis" sibling without changing the
// validation result contract.
type CredentialReport struct {
	SchemaVersion int                        `json:"schema_version"`
	RuleID        string                     `json:"rule_id"`
	Attributes    map[string]string          `json:"attributes,omitempty"`
	Validation    CredentialValidationReport `json:"validation"`
}

// CredentialValidationReport is the validation portion of a credential report.
type CredentialValidationReport struct {
	Status        ValidationStatus               `json:"status"`
	Reason        string                         `json:"reason,omitempty"`
	Metadata      map[string]any                 `json:"metadata,omitempty"`
	ComponentSets []CredentialComponentSetReport `json:"component_sets,omitempty"`
}

// CredentialComponentSetReport describes one validated set of companion credentials.
type CredentialComponentSetReport struct {
	Status     ValidationStatus            `json:"status,omitempty"`
	Reason     string                      `json:"reason,omitempty"`
	Components []CredentialComponentReport `json:"components"`
}

// CredentialComponentReport identifies one component and whether the rule
// declares it optional.
type CredentialComponentReport struct {
	RuleID   string `json:"rule_id"`
	Optional bool   `json:"optional,omitempty"`
}

// CredentialRuleList is the versioned output produced by validate --list.
type CredentialRuleList struct {
	SchemaVersion int                     `json:"schema_version"`
	Rules         []CredentialRuleSummary `json:"rules"`
}

// CredentialRuleSummary describes a rule that supports direct validation.
type CredentialRuleSummary struct {
	RuleID      string                      `json:"rule_id"`
	Description string                      `json:"description,omitempty"`
	Components  []CredentialComponentReport `json:"components,omitempty"`
	Captures    []string                    `json:"captures,omitempty"`
}

// NewCredentialReport builds a redacted report from a validated finding.
func NewCredentialReport(finding Finding, secrets []string, includeEmpty bool) CredentialReport {
	secrets = credentialSecretsForRedaction(secrets)
	metadata := sanitizeCredentialMetadata(finding.ValidationMeta, secrets, includeEmpty)
	result := CredentialReport{
		SchemaVersion: CredentialReportSchemaVersion,
		RuleID:        finding.RuleID,
		Attributes:    sanitizeCredentialAttributes(finding.Attributes, secrets),
		Validation: CredentialValidationReport{
			Status:   finding.ValidationStatus,
			Reason:   sanitizeCredentialString(finding.ValidationReason, secrets),
			Metadata: metadata,
		},
	}
	for _, set := range finding.ComponentSets {
		setResult := CredentialComponentSetReport{
			Status: set.ValidationStatus,
			Reason: sanitizeCredentialString(set.ValidationReason, secrets),
		}
		for _, component := range set.Components {
			setResult.Components = append(setResult.Components, CredentialComponentReport{
				RuleID:   component.RuleID,
				Optional: component.Optional,
			})
		}
		sort.Slice(setResult.Components, func(i, j int) bool {
			return setResult.Components[i].RuleID < setResult.Components[j].RuleID
		})
		result.Validation.ComponentSets = append(result.Validation.ComponentSets, setResult)
	}
	return result
}

func sanitizeCredentialAttributes(attributes map[string]string, secrets []string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(attributes))
	for key, value := range attributes {
		out[sanitizeCredentialString(key, secrets)] = sanitizeCredentialString(value, secrets)
	}
	return out
}

func sanitizeCredentialMetadata(metadata map[string]any, secrets []string, includeEmpty bool) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]any, len(metadata))
	for key, value := range metadata {
		if !includeEmpty {
			if value == nil {
				continue
			}
			if text, ok := value.(string); ok && text == "" {
				continue
			}
		}
		out[sanitizeCredentialString(key, secrets)] = sanitizeCredentialValue(value, secrets)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeCredentialValue(value any, secrets []string) any {
	switch typed := value.(type) {
	case string:
		return sanitizeCredentialString(typed, secrets)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			out[sanitizeCredentialString(key, secrets)] = sanitizeCredentialValue(child, secrets)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(typed))
		for key, child := range typed {
			out[sanitizeCredentialString(key, secrets)] = sanitizeCredentialString(child, secrets)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = sanitizeCredentialValue(child, secrets)
		}
		return out
	case []string:
		out := make([]string, len(typed))
		for i, child := range typed {
			out[i] = sanitizeCredentialString(child, secrets)
		}
		return out
	default:
		return value
	}
}

func sanitizeCredentialString(value string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
}

func credentialSecretsForRedaction(secrets []string) []string {
	ordered := make([]string, 0, len(secrets))
	seen := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if _, ok := seen[secret]; ok {
			continue
		}
		seen[secret] = struct{}{}
		ordered = append(ordered, secret)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(ordered[i]) > len(ordered[j])
	})
	return ordered
}
