# Development Setup

Set up a local development environment for contributing to kube-chainsaw.

---

## Prerequisites

- Python 3.9 or later
- Git
- (Optional) Docker for testing the container image

---

## Clone and Install

Clone the repository:

```bash
git clone https://github.com/ugiordan/kube-chainsaw.git
cd kube-chainsaw
```

Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
```

Install in editable mode with dev dependencies:

```bash
pip install -e ".[dev]"
```

This installs:

- `kube-chainsaw` package in editable mode
- `pytest` for testing
- `black` for code formatting
- `ruff` for linting
- `mypy` for type checking

---

## Run Tests

Run the full test suite:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=kube_chainsaw --cov-report=html
open htmlcov/index.html  # View coverage report
```

Run specific tests:

```bash
pytest tests/test_rules.py::test_wildcard_verbs
```

---

## Code Quality

Format code with Black:

```bash
black .
```

Lint with Ruff:

```bash
ruff check .
```

Type-check with mypy:

```bash
mypy kube_chainsaw/
```

---

## Project Structure

```
kube-chainsaw/
├── kube_chainsaw/          # Main package
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── scanner.py          # Scanner class
│   ├── graph.py            # Graph builder
│   ├── rules/              # Detection rules
│   │   ├── __init__.py
│   │   ├── base.py         # Base rule class
│   │   ├── kc001_wildcard_verbs.py
│   │   ├── kc002_wildcard_resources.py
│   │   └── ...
│   ├── reporters/          # Output formatters
│   │   ├── console.py
│   │   ├── json.py
│   │   └── sarif.py
│   └── models/             # Data models
│       ├── finding.py
│       ├── resource.py
│       └── location.py
├── tests/                  # Test suite
│   ├── fixtures/           # Test YAML manifests
│   ├── test_scanner.py
│   ├── test_rules.py
│   └── test_reporters.py
├── docs/                   # Sphinx documentation
├── site/                   # MkDocs Material site
├── pyproject.toml          # Project metadata
└── README.md
```

---

## Running Locally

Test the CLI during development:

```bash
python -m kube_chainsaw.cli scan tests/fixtures/
```

Or use the installed script:

```bash
kube-chainsaw scan tests/fixtures/
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
mkdocs build
```

---

## Docker Development

Build the Docker image:

```bash
docker build -t kube-chainsaw:dev .
```

Run the container:

```bash
docker run --rm -v $(pwd)/tests/fixtures:/fixtures kube-chainsaw:dev scan /fixtures
```

---

## Debugging

Use pytest with pdb:

```bash
pytest --pdb
```

Enable verbose logging:

```bash
kube-chainsaw scan tests/fixtures/ --verbose
```

---

## Pre-Commit Hooks

Install pre-commit hooks:

```bash
pip install pre-commit
pre-commit install
```

This runs Black, Ruff, and mypy on every commit.

---

## Next Steps

- [Adding Rules](rules.md): Create new detection rules
- [Architecture](../architecture/overview.md): Understand the codebase structure
- [Python API](../reference/api.md): Library usage examples
