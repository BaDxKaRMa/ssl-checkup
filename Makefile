.PHONY: help sync test test-unit test-integration test-verbose test-coverage lint format clean build security check-all ci dev-setup pre-commit

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

sync:  ## Sync development dependencies with uv
	uv sync

test:  ## Run tests
	uv run pytest tests/ -v

test-unit:  ## Run unit tests only
	uv run pytest tests/ -v -m "not integration"

test-integration:  ## Run integration tests only
	uv run pytest tests/test_integration.py -v

test-verbose:  ## Run tests with verbose output and long tracebacks
	uv run pytest tests/ -v --tb=long

test-coverage:  ## Run tests with coverage report
	uv run pytest tests/ -v --cov=ssl_checkup --cov-report=term-missing --cov-report=html

lint:  ## Run linting tools
	uv run black --check ssl_checkup/ tests/
	uv run flake8 ssl_checkup/ tests/
	uv run mypy ssl_checkup/ --ignore-missing-imports

format:  ## Format code with black
	uv run black ssl_checkup/ tests/

security:  ## Run security checks
	uv run bandit -r ssl_checkup/

clean:  ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build:  ## Build the package
	uv run python -m build

check-all:  ## Run all checks (tests, linting, security)
	$(MAKE) test-coverage
	$(MAKE) lint
	$(MAKE) security

ci:  ## Run CI pipeline locally
	$(MAKE) clean
	$(MAKE) sync
	$(MAKE) check-all

dev-setup:  ## Set up development environment with uv
	uv sync

pre-commit:  ## Run pre-commit checks
	$(MAKE) format
	$(MAKE) lint
	$(MAKE) test
