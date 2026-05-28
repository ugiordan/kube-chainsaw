# Installation

kube-chainsaw is distributed as a Python package, Docker image, and GitHub Action.

---

## pip (Recommended)

Install from PyPI:

```bash
pip install kube-chainsaw
```

Verify installation:

```bash
kube-chainsaw --version
```

---

## Docker

Pull the latest image:

```bash
docker pull ghcr.io/ugiordan/kube-chainsaw:latest
```

Run a scan:

```bash
docker run --rm -v $(pwd)/manifests:/manifests \
  ghcr.io/ugiordan/kube-chainsaw:latest scan /manifests
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
        uses: ugiordan/kube-chainsaw-action@v1
        with:
          directory: manifests/
          fail-on-severity: high
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: kube-chainsaw.sarif
        if: always()
```

The action automatically generates SARIF output and uploads it to GitHub Code Scanning.

---

## From Source

Clone and install in development mode:

```bash
git clone https://github.com/ugiordan/kube-chainsaw.git
cd kube-chainsaw
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -e .
```

See [Development Setup](../contributing/setup.md) for full development environment setup.

---

## Requirements

- Python 3.9 or later
- No external dependencies for basic scanning
- Optional: `rich` for enhanced console output (auto-installed with pip)

---

## Next Steps

- [Quick Start Tutorial](quickstart.md)
- [CLI Reference](../reference/cli.md)
- [CI Integration Guide](../guides/ci-integration.md)
