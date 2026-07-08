# Contributing to kube-chainsaw

Contributions are welcome. Whether it's a bug report, a new detection rule, a docs fix, or a feature you've been thinking about, I'd like to hear about it.

## Ways to contribute

**Report a bug or suggest a feature**: Open an [issue](https://github.com/ugiordan/kube-chainsaw/issues). Describe what you expected, what happened, and ideally include a minimal YAML manifest that reproduces the problem.

**Add a detection rule**: kube-chainsaw currently has 15 rules. If you've seen an RBAC misconfiguration pattern that isn't covered, propose it as an issue or submit a PR. See `pkg/analyzer/rules.go` for how existing rules work.

**Fix a false positive**: If kube-chainsaw flags something that isn't actually a risk, open an issue with the YAML that triggers it and explain why it's safe. Even better, submit a PR with a test case.

**Improve documentation**: The docs site lives in `site/docs/`. Typos, unclear explanations, missing examples: all fair game.

**Write a test**: More test coverage is always useful. Tests live alongside the code they test (`*_test.go`).

## Getting started

### Prerequisites

- Go 1.23+
- `golangci-lint` (for linting)

### Build and test

```bash
git clone https://github.com/ugiordan/kube-chainsaw.git
cd kube-chainsaw

go build ./...
go test ./... -v -race
go vet ./...
```

### Run against sample manifests

```bash
go run ./cmd/kube-chainsaw testdata/
```

### Lint

```bash
golangci-lint run
```

## Submitting a PR

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Add or update tests for what you changed
4. Run `go test ./... -race` and `golangci-lint run` locally
5. Open a PR with a clear description of what you changed and why

I review PRs personally. For small fixes I'll usually merge within a day or two. For larger changes, I might suggest some modifications, but I'll always explain why.

## Code structure

```
cmd/kube-chainsaw/     CLI entry point
pkg/
  analyzer/            Detection rules and graph traversal
  loader/              YAML manifest parsing
  models/              Data types (Finding, Severity, etc.)
  reporter/            Output formatters (console, JSON, SARIF)
  suppression/         Suppression file handling
testdata/              Sample manifests for testing
site/docs/             Documentation (MkDocs)
```

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
