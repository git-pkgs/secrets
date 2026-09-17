package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultMaxBlobSize                    = 1 << 20
	defaultValidateTimeout                = 5 * time.Second
	defaultFindingExitCode                = 1
	defaultValidationWorkers              = 4
	defaultValidationMaxRequestsPerTarget = 100
	defaultValidationRequestsPerSecond    = 5
)

var (
	workers                        int
	maxBlobSize                    int64
	format                         string
	redact                         bool
	attribute                      bool
	validate                       bool
	validateTimeout                time.Duration
	validationWorkers              int
	validationMaxRequestsPerTarget int
	validationRequestsPerSecond    float64
	validationEnvVars              []string
	cpuProfile                     string
	memProfile                     string
	ruleTimings                    string
	findingExitCode                int
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "secrets:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:               "secrets",
		Short:             "Find leaked credentials across Git history",
		SilenceErrors:     true,
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}

	scan := &cobra.Command{
		Use:   "scan [repo]",
		Short: "Scan every blob in the repository's history",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return scanCmd(cmd.Context(), repoArg(args))
		},
	}
	scan.Flags().IntVar(&workers, "workers", runtime.GOMAXPROCS(0), "concurrent blob readers")
	scan.Flags().Int64Var(&maxBlobSize, "max-blob-size", defaultMaxBlobSize, "skip blobs larger than this many bytes")
	scan.Flags().StringVar(&format, "format", "tsv", "output format: tsv, json, sarif")
	scan.Flags().BoolVar(&redact, "redact", true, "mask matched secrets in output")
	scan.Flags().BoolVar(&attribute, "attribute", true, "walk history to attribute findings to commit and path")
	scan.Flags().BoolVar(&validate, "validate", false, "verify matched credentials against their provider")
	scan.Flags().DurationVar(&validateTimeout, "validate-timeout", defaultValidateTimeout, "per-request timeout for --validate")
	scan.Flags().IntVar(&validationWorkers, "validation-workers", defaultValidationWorkers, "concurrent credential validations")
	scan.Flags().IntVar(&validationMaxRequestsPerTarget, "validation-max-requests-per-target", defaultValidationMaxRequestsPerTarget, "maximum validation requests per target; 0 disables")
	scan.Flags().Float64Var(&validationRequestsPerSecond, "validation-requests-per-second", defaultValidationRequestsPerSecond, "maximum validation requests per second; 0 disables")
	scan.Flags().StringSliceVar(&validationEnvVars, "validation-env-vars", nil, "environment variables available to validation rules")
	scan.Flags().StringVar(&cpuProfile, "cpuprofile", "", "write a CPU profile of blob detection to file")
	scan.Flags().StringVar(&memProfile, "memprofile", "", "write a heap profile after blob detection to file")
	scan.Flags().StringVar(&ruleTimings, "rule-timings", "", "write per-rule detection timings as CSV")
	scan.Flags().IntVar(&findingExitCode, "exit-code", defaultFindingExitCode, "exit status when findings are found; 0 disables")

	rules := &cobra.Command{
		Use:   "rules",
		Short: "List loaded detection rules",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return rulesCmd()
		},
	}

	root.AddCommand(scan, rules)
	return root
}

type findingExitError struct {
	code int
}

func (e findingExitError) Error() string { return "findings detected" }

func (e findingExitError) ExitCode() int { return e.code }

func validateScanOptions() error {
	if findingExitCode < 0 || findingExitCode > 255 {
		return fmt.Errorf("--exit-code must be between 0 and 255")
	}
	if validateTimeout <= 0 {
		return fmt.Errorf("--validate-timeout must be greater than zero")
	}
	if validationWorkers <= 0 {
		return fmt.Errorf("--validation-workers must be greater than zero")
	}
	if validationMaxRequestsPerTarget < 0 {
		return fmt.Errorf("--validation-max-requests-per-target must be non-negative")
	}
	if math.IsNaN(validationRequestsPerSecond) || math.IsInf(validationRequestsPerSecond, 0) || validationRequestsPerSecond < 0 {
		return fmt.Errorf("--validation-requests-per-second must be a finite non-negative number")
	}
	return nil
}

func repoArg(args []string) string {
	if len(args) == 0 {
		return "."
	}
	return args[0]
}
