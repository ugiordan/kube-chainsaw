# Installation

kube-chainsaw is a compiled Go binary distributed via GitHub Releases, Docker, and GitHub Action.

---

## Binary (Recommended)

### Linux

```bash
curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_linux_amd64.tar.gz | tar xz
sudo mv kube-chainsaw /usr/local/bin/
```

### macOS

```bash
# Intel
curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_darwin_amd64.tar.gz | tar xz
sudo mv kube-chainsaw /usr/local/bin/

# Apple Silicon
curl -sL https://github.com/ugiordan/kube-chainsaw/releases/latest/download/kube-chainsaw_darwin_arm64.tar.gz | tar xz
sudo mv kube-chainsaw /usr/local/bin/
```

### Windows

Download the latest release from [GitHub Releases](https://github.com/ugiordan/kube-chainsaw/releases) and extract `kube-chainsaw.exe` to a directory in your PATH.

Verify installation:

```bash
kube-chainsaw --version
```

---

## Go Install

Install from source using Go:

```bash
go install github.com/ugiordan/kube-chainsaw/cmd/kube-chainsaw@latest
```

---

## Docker

Pull the latest image:

```bash
docker pull ghcr.io/ugiordan/kube-chainsaw:latest
```

Run a scan:

```bash
docker run --rm -v $(pwd)/manifests:/scan \
  ghcr.io/ugiordan/kube-chainsaw:latest /scan
```

---

## GitHub Action

Add to your workflow:

```yaml
name: RBAC Security Scan

on: [push, pull_request]

jobs:
  rbac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run kube-chainsaw
        uses: ugiordan/kube-chainsaw@v1
        with:
          paths: config/ deploy/
          fail-on: HIGH
          format: sarif
          output: kube-chainsaw.sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: kube-chainsaw.sarif
        if: always()
```

The action downloads the binary, verifies checksums, and runs the scan.

---

## Requirements

- No dependencies (static binary)
- Works on Linux, macOS (Intel + Apple Silicon), and Windows
- No Python, Docker, or runtime dependencies required

---

## Next Steps

- [Quick Start Tutorial](quickstart.md)
- [CLI Reference](../reference/cli.md)
- [CI Integration Guide](../guides/ci-integration.md)
