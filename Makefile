.PHONY: dev test lint type-check build deploy-local clean security-scan help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

dev: ## Run proxy in development mode
	docker-compose up -d redis
	python -m uvicorn src.main:app --reload --port 8080

admin: ## Run admin dashboard in development mode
	python -m uvicorn admin.main:app --reload --port 8090

test: ## Run full test suite
	pytest tests/ -q --tb=short --ignore=tests/test_admin_integration.py

test-verbose: ## Run tests with verbose output
	pytest tests/ -v --tb=short --ignore=tests/test_admin_integration.py

lint: ## Run linter (ruff) with auto-fix
	ruff check src/ admin/ tests/ --fix
	ruff format src/ admin/ tests/

type-check: ## Run mypy type checker
	mypy src/ --ignore-missing-imports

build: ## Build Docker images
	docker build -t sentinel-gateway-proxy:dev -f Dockerfile .
	docker build -t sentinel-gateway-admin:dev -f docker/Dockerfile.admin .

security-scan: ## Run security scans (pip-audit + trivy)
	pip-audit
	@echo "Run 'trivy image sentinel-gateway-proxy:dev' for container scan"

deploy-local: ## Deploy full stack locally with docker-compose
	docker-compose up --build -d
	@echo "Waiting for services to start..."
	@sleep 5
	@echo "Proxy: http://localhost:8080/health"
	@echo "Admin: http://localhost:8090"

clean: ## Remove containers, volumes, and caches
	docker-compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true

smoke-test: ## Run security smoke test against local deployment
	python scripts/security-smoke-test.py --host http://localhost:8080

validate: ## Run deployment validation script
	./scripts/validate-deployment.sh --skip-backend
