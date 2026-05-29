# Development Setup

Set up a local development environment for contributing to kube-chainsaw.

---

## Prerequisites

- Go 1.21 or later
- Git
- (Optional) Docker for testing the container image
- (Optional) golangci-lint for linting

---

## Clone and Install

Clone the repository:

```bash
git clone https://github.com/ugiordan/kube-chainsaw.git
cd kube-chainsaw
```

Install dependencies:

```bash
go mod download
```

Build the binary:

```bash
go build -o kube-chainsaw ./cmd/kube-chainsaw
```

Install to GOPATH/bin:

```bash
go install ./cmd/kube-chainsaw
```

---

## Run Tests

Run the full test suite:

```bash
go test ./...
```

Run with coverage:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Run specific tests:

```bash
go test ./pkg/analyzer -run TestWildcardVerbs
```

---

## Code Quality

Format code:

```bash
go fmt ./...
```

Vet code:

```bash
go vet ./...
```

Lint with golangci-lint (if installed):

```bash
golangci-lint run
```

Install golangci-lint:

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

---

## Project Structure

```
kube-chainsaw/
├── cmd/
│   └── kube-chainsaw/
│       └── main.go           # CLI entry point
├── pkg/
│   ├── analyzer/
│   │   ├── analyzer.go       # Main analysis logic
│   │   └── rules.go          # Detection rule definitions
│   ├── loader/
│   │   └── loader.go         # YAML manifest loading
│   ├── models/
│   │   └── models.go         # Data structures
│   ├── reporter/
│   │   ├── console.go        # Console output
│   │   ├── json.go           # JSON output
│   │   └── sarif.go          # SARIF output
│   └── suppression/
│       └── suppression.go    # Suppression loading and matching
├── internal/
│   └── version/
│       └── version.go        # Version metadata
├── tests/
│   └── fixtures/             # Test YAML manifests
├── site/                     # MkDocs Material site
├── .goreleaser.yaml          # Release configuration
├── .github/
│   └── action.yml            # GitHub Action
├── go.mod
└── README.md
```

---

## Running Locally

Test the CLI during development:

```bash
go run ./cmd/kube-chainsaw k8s/
```

Or use the built binary:

```bash
./kube-chainsaw k8s/
```

---

## Building Documentation

Build MkDocs site:

```bash
cd site
mkdocs serve
```

Open `http://127.0.0.1:8000/` to preview.

Build static HTML:

```bash
mkdocs build --strict
```

---

## Docker Development

Build the Docker image:

```bash
docker build -t kube-chainsaw:dev .
```

Run the container:

```bash
docker run --rm -v $(pwd)/tests/fixtures:/fixtures kube-chainsaw:dev /fixtures
```

---

## Release Process

Releases are automated via goreleaser on Git tags:

1. Tag a release:

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

2. GitHub Actions builds binaries, Docker images, and creates a GitHub Release
3. Artifacts include:
   - Linux/macOS/Windows binaries (amd64, arm64)
   - Docker image pushed to ghcr.io
   - Checksums file

---

## Debugging

Use Delve for debugging:

```bash
go install github.com/go-delve/delve/cmd/dlv@latest
dlv debug ./cmd/kube-chainsaw -- k8s/
```

Enable verbose logging:

```bash
kube-chainsaw k8s/ --verbose
```

---

## Next Steps

- [Adding Rules](rules.md): Create new detection rules
- [Architecture](../architecture/overview.md): Understand the codebase structure
- [Go API](../reference/go-api.md): Library usage examples
