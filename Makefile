PYTHON ?= python3
VENV ?= .venv

.PHONY: help venv install lint format typecheck security test attacks demo gui clean

help:
	@echo "make venv        - create an isolated virtualenv"
	@echo "make install     - install package + dev tools into $(VENV)"
	@echo "make lint        - ruff check + format check"
	@echo "make format      - ruff format (auto-fix style)"
	@echo "make typecheck   - mypy (strict-adjacent, see pyproject.toml)"
	@echo "make security    - bandit + pip-audit"
	@echo "make test        - pytest unit + e2e suites"
	@echo "make attacks     - run the 15-case attack simulator"
	@echo "make demo        - run the full three-process demo"
	@echo "make gui         - open the interactive web dashboard (localhost only)"
	@echo "make clean       - remove caches and runtime state"

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -e ".[dev]"

lint:
	$(VENV)/bin/ruff check src tests
	$(VENV)/bin/ruff format --check src tests

format:
	$(VENV)/bin/ruff format src tests
	$(VENV)/bin/ruff check --fix src tests

typecheck:
	$(VENV)/bin/mypy

security:
	$(VENV)/bin/bandit -c pyproject.toml -r src
	$(VENV)/bin/pip-audit -r requirements.txt

test:
	$(VENV)/bin/pytest

attacks:
	$(VENV)/bin/python -m securepay attack --all

demo:
	$(VENV)/bin/python -m securepay demo

gui:
	$(VENV)/bin/python -m securepay gui

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	rm -rf network
	find . -name __pycache__ -type d -exec rm -rf {} +
