package main

import (
	"io"
	"sort"

	"github.com/betterleaks/betterleaks/config"
	"github.com/git-pkgs/sarif"
)

const (
	sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion   = "2.1.0"
	toolName       = "secrets"
	toolURI        = "https://github.com/git-pkgs/secrets"
)

func sarifEmitter(w io.Writer, cfg *config.Config, redact bool) (emitFunc, func() error, error) {
	ruleIndex := map[string]int{}
	var descriptors []sarif.ReportingDescriptor
	ids := make([]string, 0, len(cfg.Rules))
	for id := range cfg.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := cfg.Rules[id]
		ruleIndex[id] = len(descriptors)
		d := sarif.NewReportingDescriptor()
		d.ID = id
		d.Name = id
		d.ShortDescription = sarif.MultiformatMessageString{Text: r.Description}
		descriptors = append(descriptors, d)
	}

	var results []sarif.Result
	emit := func(f Finding) error {
		reason, metadata := validationDetails(f.Report, redact)
		r := maybeRedact(f.Report, redact)
		result := sarif.NewResult()
		result.RuleID = r.RuleID
		if idx, ok := ruleIndex[r.RuleID]; ok {
			result.RuleIndex = idx
		}
		result.Level = "error"
		result.Message = sarif.Message{Text: r.Description}
		result.PartialFingerprints = map[string]string{
			"blob":   f.Blob,
			"commit": f.Commit,
		}
		properties := sarif.PropertyBag{}
		if r.ValidationStatus != "" {
			properties["validation_status"] = r.ValidationStatus
		}
		if reason != "" {
			properties["validation_reason"] = reason
		}
		if len(metadata) > 0 {
			properties["validation_metadata"] = metadata
		}
		if len(properties) > 0 {
			result.Properties = properties
		}
		results = append(results, resultWithLocation(result, f, r.StartLine, r.EndLine, r.StartColumn, r.EndColumn, r.Secret))
		return nil
	}

	done := func() error {
		run := sarif.NewRun()
		run.Tool = sarif.Tool{Driver: sarif.ToolComponent{
			Name:           toolName,
			InformationURI: toolURI,
			Rules:          descriptors,
		}}
		run.Results = results
		log := sarif.Log{SchemaURI: sarifSchemaURI, Version: sarifVersion, Runs: []sarif.Run{run}}
		return sarif.Dump(&log, w, true)
	}
	return emit, done, nil
}

func resultWithLocation(result sarif.Result, f Finding, startLine, endLine, startCol, endCol int, snippet string) sarif.Result {
	region := sarif.NewRegion()
	region.StartLine = max(startLine, 1)
	if endLine > 0 {
		region.EndLine = endLine
	}
	if startCol > 0 {
		region.StartColumn = startCol
	}
	if endCol > 0 {
		region.EndColumn = endCol
	}
	region.Snippet = sarif.ArtifactContent{Text: snippet}
	uri := f.Path
	if uri == "" {
		uri = f.Blob
	}
	loc := sarif.NewLocation()
	loc.PhysicalLocation = sarif.PhysicalLocation{
		ArtifactLocation: sarif.ArtifactLocation{URI: uri},
		Region:           region,
	}
	result.Locations = []sarif.Location{loc}
	return result
}
