"""CLI entrypoint for kube-chainsaw."""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from kube_chainsaw import __version__
from kube_chainsaw.analyzer import RBACAnalyzer
from kube_chainsaw.loader import load_manifests
from kube_chainsaw.models import Finding, Severity
from kube_chainsaw.plugins import load_attack_scenarios
from kube_chainsaw.reporters.console import ConsoleReporter
from kube_chainsaw.reporters.json_reporter import JsonReporter
from kube_chainsaw.reporters.sarif import SarifReporter
from kube_chainsaw.suppressions import apply_suppressions, load_suppressions


def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="kube-chainsaw",
        description="Graph-level RBAC privilege chain analysis for Kubernetes manifests",
    )

    parser.add_argument(
        "paths",
        nargs="+",
        help="Directories to scan for Kubernetes manifests",
    )

    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "WARNING", "INFO"],
        default="CRITICAL",
        help="Minimum severity level to exit with code 1 (default: CRITICAL)",
    )

    parser.add_argument(
        "--format",
        choices=["console", "json", "sarif"],
        default="console",
        help="Output format for stdout (default: console)",
    )

    parser.add_argument(
        "--output",
        type=str,
        help="Write structured output to file (.sarif extension = SARIF, else JSON)",
    )

    parser.add_argument(
        "--output-format",
        choices=["json", "sarif"],
        help="Override output file format (default: infer from extension)",
    )

    parser.add_argument(
        "--exclude-dirs",
        type=str,
        help="Comma-separated list of additional directories to exclude",
    )

    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Disable default directory exclusion list",
    )

    parser.add_argument(
        "--suppressions",
        type=str,
        help="Path to YAML file containing suppression rules",
    )

    parser.add_argument(
        "--include-attack-scenarios",
        action="store_true",
        help="Include attack scenarios in output (requires kube-chainsaw-scenarios plugin)",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stdout output (only write to --output if specified)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Parse exclude-dirs
    exclude_dirs: Optional[List[str]] = None
    if args.exclude_dirs:
        exclude_dirs = [d.strip() for d in args.exclude_dirs.split(",")]

    # Load manifests
    resources = load_manifests(
        paths=args.paths,
        exclude_dirs=exclude_dirs,
        use_default_excludes=not args.no_default_excludes,
    )

    # Check if resources are empty
    if resources.is_empty():
        print("No RBAC resources found", file=sys.stderr)

    # Analyze
    analyzer = RBACAnalyzer()
    analyzer.load(resources)
    findings = analyzer.analyze()

    # Apply suppressions if provided
    if args.suppressions:
        try:
            suppressions = load_suppressions(args.suppressions)
            apply_suppressions(findings, suppressions)
        except FileNotFoundError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(2)

    # Include attack scenarios if requested
    if args.include_attack_scenarios:
        scenarios = load_attack_scenarios(warn_if_missing=True)
        # Merge scenarios into findings (this is a placeholder logic)
        # The actual merging would depend on how scenarios are structured
        # For now, we just ensure the plugin is loaded
        pass

    # Determine stdout reporter
    if args.format == "console":
        reporter = ConsoleReporter()
    elif args.format == "json":
        reporter = JsonReporter()
    elif args.format == "sarif":
        reporter = SarifReporter()
    else:
        reporter = ConsoleReporter()

    # Render to stdout unless --quiet
    if not args.quiet:
        output = reporter.render(findings, include_scenarios=args.include_attack_scenarios)
        print(output)

    # Write to file if --output specified
    if args.output:
        # Determine file format
        if args.output_format:
            file_format = args.output_format
        else:
            # Infer from extension
            if args.output.endswith(".sarif"):
                file_format = "sarif"
            else:
                file_format = "json"

        # Select file reporter
        if file_format == "sarif":
            file_reporter = SarifReporter()
        else:
            file_reporter = JsonReporter()

        # Render and write
        try:
            output = file_reporter.render(findings, include_scenarios=args.include_attack_scenarios)
            Path(args.output).write_text(output)
        except IOError as e:
            print(f"ERROR: Failed to write output file: {e}", file=sys.stderr)
            sys.exit(2)

    # Determine exit code
    fail_on_severity = Severity.from_str(args.fail_on)
    has_failure = any(
        not finding.suppressed and finding.severity >= fail_on_severity
        for finding in findings
    )

    sys.exit(1 if has_failure else 0)


if __name__ == "__main__":
    main()
