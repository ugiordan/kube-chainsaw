# Go Library Usage

kube-chainsaw can be used as a Go library for custom integrations and tooling.

---

## Installation

```bash
go get github.com/ugiordan/kube-chainsaw
```

---

## Basic Usage

```go
package main

import (
	"fmt"
	"github.com/ugiordan/kube-chainsaw/pkg/analyzer"
	"github.com/ugiordan/kube-chainsaw/pkg/loader"
	"github.com/ugiordan/kube-chainsaw/pkg/reporter"
)

func main() {
	// Load manifests
	opts := loader.DefaultOptions()
	resources, err := loader.LoadManifests([]string{"k8s/"}, opts)
	if err != nil {
		panic(err)
	}

	// Analyze
	findings := analyzer.Analyze(resources)

	// Report
	consoleReporter := &reporter.ConsoleReporter{}
	output, _ := consoleReporter.Render(findings)
	fmt.Print(output)
}
```

---

## Loading Manifests

The `loader` package parses YAML manifests into structured data:

```go
package main

import (
	"github.com/ugiordan/kube-chainsaw/pkg/loader"
)

func main() {
	// Use default options
	opts := loader.DefaultOptions()
	
	// Or customize
	opts.ExcludeDirs = append(opts.ExcludeDirs, "staging", "dev")
	opts.UseDefaultExcludes = true
	opts.MaxFileSize = 10 * 1024 * 1024 // 10 MB
	opts.MaxDocsPerFile = 10000

	// Load from paths
	resources, err := loader.LoadManifests([]string{"k8s/", "deploy/"}, opts)
	if err != nil {
		// Handle error
	}

	// Check what was loaded
	if resources.IsEmpty() {
		// No RBAC resources found
	}
}
```

---

## Analyzing Resources

The `analyzer` package runs detection rules:

```go
package main

import (
	"github.com/ugiordan/kube-chainsaw/pkg/analyzer"
	"github.com/ugiordan/kube-chainsaw/pkg/loader"
	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

func main() {
	resources, _ := loader.LoadManifests([]string{"k8s/"}, loader.DefaultOptions())
	
	// Run all detection rules
	findings := analyzer.Analyze(resources)

	// Filter by severity
	for _, f := range findings {
		if f.Severity >= models.SeverityHigh {
			// Handle high/critical findings
		}
	}
}
```

---

## Applying Suppressions

The `suppression` package loads and applies suppressions:

```go
package main

import (
	"github.com/ugiordan/kube-chainsaw/pkg/analyzer"
	"github.com/ugiordan/kube-chainsaw/pkg/loader"
	"github.com/ugiordan/kube-chainsaw/pkg/suppression"
)

func main() {
	resources, _ := loader.LoadManifests([]string{"k8s/"}, loader.DefaultOptions())
	findings := analyzer.Analyze(resources)

	// Load suppressions
	sups, err := suppression.LoadSuppressions("suppressions.yaml")
	if err != nil {
		// Handle error
	}

	// Apply suppressions (modifies findings in place)
	findings = suppression.ApplySuppressions(findings, sups)

	// Check suppression status
	for _, f := range findings {
		if f.Suppressed {
			// This finding was suppressed
		}
	}
}
```

---

## Rendering Output

The `reporter` package formats findings:

### Console Output

```go
package main

import (
	"fmt"
	"github.com/ugiordan/kube-chainsaw/pkg/reporter"
)

func main() {
	// findings := analyzer.Analyze(resources)
	
	consoleReporter := &reporter.ConsoleReporter{}
	output, err := consoleReporter.Render(findings)
	if err != nil {
		// Handle error
	}
	fmt.Print(output)
}
```

### JSON Output

```go
package main

import (
	"os"
	"github.com/ugiordan/kube-chainsaw/pkg/reporter"
)

func main() {
	// findings := analyzer.Analyze(resources)
	
	jsonReporter := &reporter.JSONReporter{}
	output, err := jsonReporter.Render(findings)
	if err != nil {
		// Handle error
	}
	
	os.WriteFile("results.json", []byte(output), 0644)
}
```

### SARIF Output

```go
package main

import (
	"os"
	"github.com/ugiordan/kube-chainsaw/pkg/reporter"
)

func main() {
	// findings := analyzer.Analyze(resources)
	
	sarifReporter := &reporter.SARIFReporter{}
	output, err := sarifReporter.Render(findings)
	if err != nil {
		// Handle error
	}
	
	os.WriteFile("results.sarif", []byte(output), 0644)
}
```

---

## Data Models

### Finding

```go
type Finding struct {
	RuleID            string
	Severity          Severity  // SeverityInfo, SeverityWarning, SeverityHigh, SeverityCritical
	Title             string
	File              string
	Description       string
	Remediation       string
	ResourceKind      string
	ResourceName      string
	ResourceNamespace string
	Suppressed        bool
	Fingerprint       string  // SHA256 hash
}
```

### Severity

```go
type Severity int

const (
	SeverityInfo     Severity = 0
	SeverityWarning  Severity = 1
	SeverityHigh     Severity = 2
	SeverityCritical Severity = 3
)

// Convert to string
severity.String() // "INFO", "WARNING", "HIGH", "CRITICAL"

// Parse from string
sev, err := models.ParseSeverity("HIGH")
```

### Loaded Resources

```go
type LoadedResources struct {
	ClusterRoles        map[string]*ClusterRoleData
	Roles               map[string]*RoleData  // key: "namespace/name"
	ClusterRoleBindings []*BindingData
	RoleBindings        []*BindingData
	ServiceAccounts     map[string]*SAData  // key: "namespace/name"
	Pods                map[string]*PodData  // key: "namespace/name"
	Workloads           map[string]*WorkloadData  // key: "kind/namespace/name"
}
```

---

## Complete Example

```go
package main

import (
	"fmt"
	"os"

	"github.com/ugiordan/kube-chainsaw/pkg/analyzer"
	"github.com/ugiordan/kube-chainsaw/pkg/loader"
	"github.com/ugiordan/kube-chainsaw/pkg/models"
	"github.com/ugiordan/kube-chainsaw/pkg/reporter"
	"github.com/ugiordan/kube-chainsaw/pkg/suppression"
)

func main() {
	// Load manifests
	opts := loader.DefaultOptions()
	opts.ExcludeDirs = append(opts.ExcludeDirs, "staging")
	
	resources, err := loader.LoadManifests([]string{"k8s/"}, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading manifests: %v\n", err)
		os.Exit(2)
	}

	// Analyze
	findings := analyzer.Analyze(resources)

	// Apply suppressions
	if len(os.Args) > 1 && os.Args[1] == "--suppressions" {
		sups, err := suppression.LoadSuppressions(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading suppressions: %v\n", err)
			os.Exit(2)
		}
		findings = suppression.ApplySuppressions(findings, sups)
	}

	// Print console output
	consoleReporter := &reporter.ConsoleReporter{}
	output, _ := consoleReporter.Render(findings)
	fmt.Print(output)

	// Write SARIF
	sarifReporter := &reporter.SARIFReporter{}
	sarifOutput, _ := sarifReporter.Render(findings)
	os.WriteFile("results.sarif", []byte(sarifOutput), 0644)

	// Exit code based on severity
	for _, f := range findings {
		if !f.Suppressed && f.Severity >= models.SeverityHigh {
			os.Exit(1)
		}
	}
	os.Exit(0)
}
```

---

## Next Steps

- [CLI Reference](cli.md): Command-line usage
- [Detection Rules](rules.md): Built-in rules
- [Contributing](../contributing/rules.md): Add custom detection rules
