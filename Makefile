.PHONY: setup dev test lint typecheck build release-check check release

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

setup:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .

dev:
	@$(PY) -m jwt_workbench --help

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

typecheck:
	$(PY) -m mypy src tests

build:
	$(PY) -m compileall -q src

release-check:
	$(PY) scripts/release_check.py

check: lint typecheck test build release-check

release:
	@echo "Use PROJECT.md for release commands."
