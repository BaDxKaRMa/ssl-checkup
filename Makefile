.PHONY: help install test test-verbose test-coverage lint format clean build docs

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package in development mode
	pip install -e ".[test]"

test:  ## Run tests
	python -m pytest tests/ -v

test-verbose:  ## Run tests with verbose output
	python -m pytest tests/ -v --tb=long

test-coverage:  ## Run tests with coverage report
	python -m pytest tests/ -v --cov=ssl_checkup --cov-report=term-missing --cov-report=html

test-integration:  ## Run integration tests only
	python -m pytest tests/test_integration.py -v -m integration

test-unit:  ## Run unit tests only
	python -m pytest tests/ -v -m "not integration"

lint:  ## Run linting tools
	black --check ssl_checkup/ tests/
	flake8 ssl_checkup/ tests/
	mypy ssl_checkup/ --ignore-missing-imports

format:  ## Format code with black
	black ssl_checkup/ tests/

security:  ## Run security checks
	bandit -r ssl_checkup/

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
	python -m build

docs:  ## Generate documentation (placeholder)
	@echo "Documentation generation not yet implemented"

check-all:  ## Run all checks (tests, linting, security)
	$(MAKE) test-coverage
	$(MAKE) lint
	$(MAKE) security

ci:  ## Run CI pipeline locally
	$(MAKE) clean
	$(MAKE) install
	$(MAKE) check-all

dev-setup:  ## Set up development environment
	pip install -e ".[test]"
	pip install black flake8 mypy bandit build

# Development workflow targets
pre-commit:  ## Run pre-commit checks
	$(MAKE) format
	$(MAKE) lint
	$(MAKE) test-unit

# Example usage targets
example-basic:  ## Run basic example
	python -m ssl_checkup.main google.com

example-debug:  ## Run debug example
	python -m ssl_checkup.main google.com --debug

example-insecure:  ## Run insecure example
	python -m ssl_checkup.main badssl.com --insecure

release:  ## Create a new release (usage: make release VERSION=1.2.0)
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release VERSION=1.2.0"; exit 1; fi
	@echo "Creating release $(VERSION)..."
	@sed -i '' 's/version = "[^"]*"/version = "$(VERSION)"/' pyproject.toml
	@git add pyproject.toml
	@git commit -m "Release v$(VERSION)"
	@git tag v$(VERSION)
	@echo "Release created! Push with: git push && git push --tags"

release-push:  ## Create and push a new release (usage: make release-push VERSION=1.2.0)
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release-push VERSION=1.2.0"; exit 1; fi
	@$(MAKE) release VERSION=$(VERSION)
	@git push && git push --tags
	@echo "Release v$(VERSION) pushed! GitHub Actions will handle PyPI upload."
