.PHONY: install test lint fmt scan scan-sarif scan-vulnerable hook clean

install: ## Install dependencies
	uv sync

test: ## Run all tests
	uv run pytest -v

lint: ## Lint source and tests
	uv run ruff check src/ tests/

fmt: ## Auto-format code
	uv run ruff format src/ tests/

scan: ## Scan current directory
	uv run supsec scan .

scan-sarif: ## Scan and output SARIF (GitHub Security tab compatible)
	uv run supsec scan . --fmt sarif -o supsec-report.sarif

scan-vulnerable: ## Scan the intentionally vulnerable examples
	uv run supsec scan examples/vulnerable

scan-clean: ## Scan the clean examples (should pass)
	uv run supsec scan examples/clean

hook: ## Install git pre-commit hook
	chmod +x scripts/install-hook.sh && ./scripts/install-hook.sh

clean: ## Remove caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
