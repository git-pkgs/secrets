package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/report"
)

const redactPercent = 90

type emitFunc func(Finding) error

func newEmitter(w io.Writer, format string, cfg *config.Config, redact bool) (emitFunc, func() error, error) {
	switch format {
	case "tsv":
		return tsvEmitter(w, redact)
	case "json":
		return jsonEmitter(w, redact)
	case "sarif":
		return sarifEmitter(w, cfg, redact)
	default:
		return nil, nil, fmt.Errorf("unknown format %q", format)
	}
}

func maybeRedact(r report.Finding, redact bool) report.Finding {
	if redact {
		r.Redact(redactPercent)
	}
	return r
}

func validationDetails(r report.Finding, redact bool) (string, map[string]any) {
	if !redact {
		return r.ValidationReason, r.ValidationMeta
	}
	validation := report.NewCredentialReport(r, []string{r.Secret}, false).Validation
	return validation.Reason, validation.Metadata
}

func tsvEmitter(w io.Writer, redact bool) (emitFunc, func() error, error) {
	if _, err := fmt.Fprintln(w, "commit\tpath\tblob\trule\tline\tsecret\tentropy\tstatus\treason\tmetadata"); err != nil {
		return nil, nil, err
	}
	emit := func(f Finding) error {
		reason, metadata := validationDetails(f.Report, redact)
		var metadataJSON []byte
		var err error
		if len(metadata) > 0 {
			metadataJSON, err = json.Marshal(metadata)
			if err != nil {
				return err
			}
		}
		r := maybeRedact(f.Report, redact)
		_, err = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			f.Commit, tsvEscape(f.Path), f.Blob, r.RuleID, r.StartLine,
			tsvEscape(r.Secret), strconv.FormatFloat(float64(r.Entropy), 'f', 2, 64),
			string(r.ValidationStatus), tsvEscape(reason), tsvEscape(string(metadataJSON)))
		return err
	}
	return emit, func() error { return nil }, nil
}

func jsonEmitter(w io.Writer, redact bool) (emitFunc, func() error, error) {
	enc := json.NewEncoder(w)
	emit := func(f Finding) error {
		reason, metadata := validationDetails(f.Report, redact)
		r := maybeRedact(f.Report, redact)
		return enc.Encode(struct {
			Blob      string         `json:"blob"`
			Commit    string         `json:"commit,omitempty"`
			Date      string         `json:"date,omitempty"`
			Path      string         `json:"path,omitempty"`
			RuleID    string         `json:"rule"`
			Desc      string         `json:"description"`
			StartLine int            `json:"line"`
			Secret    string         `json:"secret"`
			Match     string         `json:"match"`
			Entropy   float32        `json:"entropy"`
			Status    string         `json:"status,omitempty"`
			Reason    string         `json:"validation_reason,omitempty"`
			Metadata  map[string]any `json:"validation_metadata,omitempty"`
		}{f.Blob, f.Commit, f.Date, f.Path, r.RuleID, r.Description, r.StartLine, r.Secret, r.Match, r.Entropy, string(r.ValidationStatus), reason, metadata})
	}
	return emit, func() error { return nil }, nil
}

func tsvEscape(s string) string {
	s = strings.ReplaceAll(s, "\t", `\t`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
