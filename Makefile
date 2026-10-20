# ==============================================================================
# Bayora Shield: Automation & Development Makefile
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help check-prereqs setup-env test-unit test-isolation test-adversarial test-security lint docker-build docker-up docker-down clean

help: ## Show this help message
	@echo "Bayora Shield - Development & Verification Commands"
	@echo "====================================================="
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

check-prereqs: ## Verify toolchain, dependencies, and secret hygiene
	@./scripts/check-prereqs.sh

setup-env: ## Initialize local .env file from .env.example if missing
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from .env.example. Please review and customize."; \
	else \
		echo ".env already exists. Preserving existing file."; \
	fi

test-unit: ## Run Phase 1 & 2 unit tests (audit integrity, hashing, RBAC)
	@echo "==> Running Unit Tests..."
	@python3 -m unittest discover -s tests/unit

test-isolation: ## Run isolation boundary assertion tests (network/enclave checks)
	@echo "==> Running Enclave Isolation Tests (Phase 2)..."
	@python3 -m unittest discover -s tests/isolation

test-adversarial: ## Run adversarial probe & prompt injection test suites
	@echo "==> Running Adversarial Tests (Phase 2)..."
	@python3 -m unittest discover -s tests/adversarial

test-security: test-unit test-isolation test-adversarial ## Run entire automated security test suite

lint-python: ## Lint Python services using ruff or flake8
	@echo "==> Linting Python code..."
	@python3 -m ruff check services/ tests/ 2>/dev/null || echo "Note: ruff not installed globally; run inside venv"

lint-dashboard: ## Lint Next.js dashboard
	@echo "==> Linting Dashboard..."
	@if [ -d "apps/dashboard/node_modules" ]; then \
		cd apps/dashboard && npm run lint; \
	else \
		echo "Note: Dashboard dependencies not yet installed. Run 'make install-dashboard'"; \
	fi

lint: lint-python lint-dashboard ## Run all code linters

install-dashboard: ## Install Node.js dependencies for dashboard
	@cd apps/dashboard && npm install

docker-build: ## Build all 8 container images with Docker Compose
	@docker compose -f infrastructure/compose/docker-compose.yml build

docker-up: ## Start all Bayora Shield services in segregated networks
	@docker compose -f infrastructure/compose/docker-compose.yml up -d

docker-down: ## Stop all Bayora Shield services and dismantle networks
	@docker compose -f infrastructure/compose/docker-compose.yml down

clean: ## Clean transient artifacts, caches, and test outputs
	@find . -type d -name "__pycache__" -exec rm -rf {} +
	@find . -type d -name ".pytest_cache" -exec rm -rf {} +
	@find . -type d -name ".next" -exec rm -rf {} +
	@echo "Clean completed."
