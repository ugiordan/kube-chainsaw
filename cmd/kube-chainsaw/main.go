package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/ugiordan/kube-chainsaw/internal/version"
	"github.com/ugiordan/kube-chainsaw/pkg/analyzer"
	"github.com/ugiordan/kube-chainsaw/pkg/loader"
	"github.com/ugiordan/kube-chainsaw/pkg/models"
	"github.com/ugiordan/kube-chainsaw/pkg/reporter"
	"github.com/ugiordan/kube-chainsaw/pkg/suppression"
)

// flags
var (
	failOn            string
	format            string
	output            string
	outputFormat      string
	excludeDirs       string
	noDefaultExcludes bool
	suppressionsPath  string
	quiet             bool
)

// Finding 9: sentinel error for threshold exceeded (instead of os.Exit inside RunE)
var errThresholdExceeded = errors.New("findings exceed severity threshold")

// Finding 11: sentinel error for runtime errors (exit code 2)
var errRuntime = errors.New("runtime error")

func main() {
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, errThresholdExceeded) {
			os.Exit(1)
		}
		// Finding 11: runtime/argument errors get exit code 2
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}

var rootCmd = &cobra.Command{
	Use:   "kube-chainsaw [paths...]",
	Short: "Kubernetes RBAC security analyzer",
	Long:  "kube-chainsaw scans Kubernetes RBAC manifests for overly permissive roles, privilege escalation risks, and security misconfigurations.",
	Args:  cobra.MinimumNArgs(1),
	RunE:  run,
	// Silence Cobra's built-in error/usage printing so we control output
	SilenceErrors: true,
	SilenceUsage:  true,
	Version:       version.Version,
}

func init() {
	rootCmd.Flags().StringVar(&failOn, "fail-on", "CRITICAL", "minimum severity to exit non-zero (CRITICAL|HIGH|WARNING|INFO)")
	rootCmd.Flags().StringVar(&format, "format", "console", "output format for stdout (console|json|sarif)")
	rootCmd.Flags().StringVar(&output, "output", "", "write report to file")
	rootCmd.Flags().StringVar(&outputFormat, "output-format", "", "format for --output file (json|sarif); inferred from extension if omitted")
	rootCmd.Flags().StringVar(&excludeDirs, "exclude-dirs", "", "comma-separated directory names to exclude")
	rootCmd.Flags().BoolVar(&noDefaultExcludes, "no-default-excludes", false, "disable default directory exclusions (.git, vendor, node_modules, bin)")
	rootCmd.Flags().StringVar(&suppressionsPath, "suppressions", "", "path to suppressions YAML file")
	rootCmd.Flags().BoolVar(&quiet, "quiet", false, "suppress stdout output")
}

func run(cmd *cobra.Command, args []string) error {
	// Parse fail-on severity
	failSeverity, err := models.ParseSeverity(failOn)
	if err != nil {
		return fmt.Errorf("invalid --fail-on value: %w", err)
	}

	// Build loader options
	loaderOpts := loader.DefaultOptions()
	if noDefaultExcludes {
		loaderOpts.UseDefaultExcludes = false
	}
	if excludeDirs != "" {
		for _, d := range strings.Split(excludeDirs, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				loaderOpts.ExcludeDirs = append(loaderOpts.ExcludeDirs, d)
			}
		}
	}

	// Step 1: Load manifests
	resources, err := loader.LoadManifests(args, loaderOpts)
	if err != nil {
		return fmt.Errorf("loading manifests: %w", err)
	}

	// Finding 15: warn when no RBAC resources are found
	if resources.IsEmpty() {
		fmt.Fprintln(os.Stderr, "WARNING: no RBAC resources found in the scanned paths. Verify the paths contain Kubernetes RBAC manifests.")
	}

	// Step 2: Analyze
	findings := analyzer.Analyze(resources)

	// Step 3: Apply suppressions
	if suppressionsPath != "" {
		sups, err := suppression.LoadSuppressions(suppressionsPath)
		if err != nil {
			return fmt.Errorf("loading suppressions: %w", err)
		}
		findings = suppression.ApplySuppressions(findings, sups)
	}

	// Step 4: Render to stdout
	if !quiet {
		stdoutReporter, err := newReporter(format)
		if err != nil {
			return err
		}
		rendered, err := stdoutReporter.Render(findings)
		if err != nil {
			return fmt.Errorf("rendering output: %w", err)
		}
		fmt.Print(rendered)
	}

	// Step 5: Write to output file
	if output != "" {
		fileFormat := resolveOutputFormat(output, outputFormat)
		fileReporter, err := newReporter(fileFormat)
		if err != nil {
			return fmt.Errorf("invalid output format: %w", err)
		}
		rendered, err := fileReporter.Render(findings)
		if err != nil {
			return fmt.Errorf("rendering file output: %w", err)
		}
		if err := os.WriteFile(output, []byte(rendered), 0644); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
	}

	// Step 6: Exit code based on severity threshold
	// Finding 9: return sentinel error instead of os.Exit
	for _, f := range findings {
		if !f.Suppressed && f.Severity >= failSeverity {
			return errThresholdExceeded
		}
	}

	return nil
}

func newReporter(format string) (reporter.Reporter, error) {
	switch strings.ToLower(format) {
	case "console":
		return &reporter.ConsoleReporter{}, nil
	case "json":
		return &reporter.JSONReporter{}, nil
	case "sarif":
		return &reporter.SARIFReporter{}, nil
	default:
		return nil, fmt.Errorf("unknown format: %q (supported: console, json, sarif)", format)
	}
}

func resolveOutputFormat(outputPath, explicit string) string {
	if explicit != "" {
		return explicit
	}
	ext := strings.ToLower(filepath.Ext(outputPath))
	if ext == ".sarif" {
		return "sarif"
	}
	return "json"
}
