"""Shared fixtures for package modules and isolated working directories."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import redactor.redact as redact_module
import redactor.unredact as unredact_module

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def redact_mod():
    """Fresh module reference for redact tests."""
    return importlib.reload(redact_module)


@pytest.fixture
def unredact_mod():
    """Fresh module reference for unredact tests."""
    return importlib.reload(unredact_module)


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Isolate cwd so redacted/dictionary.yaml stays under tmp_path."""
    monkeypatch.chdir(tmp_path)
    return tmp_path
