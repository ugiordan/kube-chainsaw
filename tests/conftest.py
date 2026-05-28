"""Shared pytest fixtures for kube-chainsaw tests."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def dangerous_dir():
    """Path to dangerous RBAC fixtures."""
    return FIXTURES_DIR / "dangerous"


@pytest.fixture
def clean_dir():
    """Path to clean RBAC fixtures."""
    return FIXTURES_DIR / "clean"


@pytest.fixture
def malformed_dir():
    """Path to malformed/invalid YAML fixtures."""
    return FIXTURES_DIR / "malformed"


@pytest.fixture
def fixtures_dir():
    """Path to fixtures root directory."""
    return FIXTURES_DIR
