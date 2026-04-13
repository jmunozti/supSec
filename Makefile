.PHONY: install test lint fmt scan scan-sarif scan-vulnerable hook clean

install: ## Install dependencies
	poetry install --no-interaction

test: ## Run all tests
	poetry run pytest -v

lint: ## Lint source and tests
	poetry run ruff check src/ tests/

fmt: ## Auto-format code
	poetry run ruff format src/ tests/

scan: ## Scan current directory
	poetry run supsec scan .

scan-sarif: ## Scan and output SARIF (GitHub Security tab compatible)
	poetry run supsec scan . --format sarif -o supsec-report.sarif

scan-vulnerable: ## Scan the intentionally vulnerable examples
	poetry run supsec scan examples/vulnerable --format console

scan-clean: ## Scan the clean examples (should pass)
	poetry run supsec scan examples/clean --format console

hook: ## Install git pre-commit hook
	chmod +x scripts/install-hook.sh && ./scripts/install-hook.sh

clean: ## Remove caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
