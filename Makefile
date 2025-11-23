# AndroSleuth - Makefile
# Shortcuts for common development and Docker tasks

.PHONY: help install test build run stop clean docker-build docker-start docker-stop docker-test docker-analyze docker-shell

# Default target
.DEFAULT_GOAL := help

# Colors
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m # No Color

##@ General

help: ## Display this help message
	@echo "$(CYAN)AndroSleuth - Makefile Commands$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(NC)\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development (Local)

install: ## Install dependencies with Poetry
	@echo "$(CYAN)Installing dependencies...$(NC)"
	poetry install -E full
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

test: ## Run unit tests
	@echo "$(CYAN)Running tests...$(NC)"
	poetry run python tests/test_basic.py
	poetry run python tests/test_shellcode.py
	poetry run python tests/test_virustotal.py
	@echo "$(GREEN)✓ Tests completed$(NC)"

format: ## Format code with black
	@echo "$(CYAN)Formatting code...$(NC)"
	poetry run black src/ tests/
	@echo "$(GREEN)✓ Code formatted$(NC)"

lint: ## Lint code with flake8
	@echo "$(CYAN)Linting code...$(NC)"
	poetry run flake8 src/ tests/
	@echo "$(GREEN)✓ Linting completed$(NC)"

type-check: ## Type check with mypy
	@echo "$(CYAN)Type checking...$(NC)"
	poetry run mypy src/
	@echo "$(GREEN)✓ Type checking completed$(NC)"

coverage: ## Run tests with coverage
	@echo "$(CYAN)Running tests with coverage...$(NC)"
	poetry run pytest tests/ --cov=src --cov-report=html --cov-report=term
	@echo "$(GREEN)✓ Coverage report generated in htmlcov/$(NC)"

##@ Docker

docker-build: ## Build Docker image
	@echo "$(CYAN)Building Docker image...$(NC)"
	docker-compose build
	@echo "$(GREEN)✓ Docker image built$(NC)"

docker-start: ## Start Docker container
	@echo "$(CYAN)Starting Docker container...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✓ Container started: AndroSleuth$(NC)"
	@make docker-status

docker-stop: ## Stop Docker container
	@echo "$(CYAN)Stopping Docker container...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Container stopped$(NC)"

docker-restart: docker-stop docker-start ## Restart Docker container

docker-test: ## Run tests in Docker container
	@echo "$(CYAN)Running tests in Docker...$(NC)"
	docker exec -it AndroSleuth poetry run python tests/test_basic.py
	docker exec -it AndroSleuth poetry run python tests/test_shellcode.py
	docker exec -it AndroSleuth poetry run python tests/test_virustotal.py
	@echo "$(GREEN)✓ Docker tests completed$(NC)"

docker-shell: ## Enter Docker container shell
	@echo "$(CYAN)Entering container shell...$(NC)"
	docker exec -it AndroSleuth /bin/bash

docker-logs: ## Show Docker container logs
	docker-compose logs -f androsleuth

docker-status: ## Show Docker container status
	@echo "$(CYAN)Container Status:$(NC)"
	@docker-compose ps
	@echo ""
	@echo "$(CYAN)Resource Usage:$(NC)"
	@docker stats AndroSleuth --no-stream 2>/dev/null || echo "Container not running"

docker-analyze: ## Analyze APK in Docker (usage: make docker-analyze APK=sample.apk)
	@if [ -z "$(APK)" ]; then \
		echo "$(YELLOW)Usage: make docker-analyze APK=<path_to_apk>$(NC)"; \
		exit 1; \
	fi
	@echo "$(CYAN)Analyzing $(APK) in Docker...$(NC)"
	@./docker-run.sh analyze $(APK) deep

##@ Cleanup

clean: ## Clean temporary files and caches
	@echo "$(CYAN)Cleaning temporary files...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .coverage htmlcov/ .mypy_cache/
	@echo "$(GREEN)✓ Cleaned$(NC)"

clean-docker: ## Remove Docker images and volumes
	@echo "$(CYAN)Removing Docker containers and images...$(NC)"
	docker-compose down -v --rmi all
	@echo "$(GREEN)✓ Docker resources cleaned$(NC)"

clean-all: clean clean-docker ## Clean everything (local + Docker)

##@ Git

commit: ## Commit changes (usage: make commit MSG="your message")
	@if [ -z "$(MSG)" ]; then \
		echo "$(YELLOW)Usage: make commit MSG=\"your commit message\"$(NC)"; \
		exit 1; \
	fi
	git add -A
	git commit -m "$(MSG)"
	@echo "$(GREEN)✓ Committed$(NC)"

push: ## Push to current branch
	git push origin $$(git branch --show-current)
	@echo "$(GREEN)✓ Pushed to origin/$$(git branch --show-current)$(NC)"

commit-push: commit push ## Commit and push (usage: make commit-push MSG="message")

##@ Quick Start

quick-start: docker-build docker-start docker-test ## Quick start: build, start, and test
	@echo ""
	@echo "$(GREEN)✓ AndroSleuth is ready!$(NC)"
	@echo "$(CYAN)Try:$(NC) make docker-analyze APK=path/to/sample.apk"
	@echo "$(CYAN)Or:$(NC) make docker-shell"

##@ Info

info: ## Show project information
	@echo "$(CYAN)AndroSleuth - Project Information$(NC)"
	@echo "Version: 1.0.0"
	@echo "Python: $$(python3 --version)"
	@echo "Poetry: $$(poetry --version)"
	@echo "Docker: $$(docker --version)"
	@echo "Docker Compose: $$(docker-compose --version)"
	@echo ""
	@echo "$(CYAN)Project Structure:$(NC)"
	@tree -L 2 -I '__pycache__|*.pyc|.venv|.git' || ls -la
