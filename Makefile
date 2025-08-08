# Makefile for Squawk DNS System
.PHONY: help setup test test-unit test-integration test-security test-performance clean build run stop logs shell

# Default target
help:
	@echo "Squawk DNS System - Available targets:"
	@echo ""
	@echo "Setup and Development:"
	@echo "  setup                 - Set up development environment"
	@echo "  setup-dev             - Set up development environment with all tools"
	@echo "  install               - Install dependencies"
	@echo "  install-dev           - Install development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  test                  - Run all tests"
	@echo "  test-unit             - Run unit tests only"
	@echo "  test-integration      - Run integration tests"
	@echo "  test-security         - Run security tests"
	@echo "  test-performance      - Run performance tests"
	@echo "  test-coverage         - Run tests with coverage report"
	@echo "  test-load             - Run load tests"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint                  - Run linting (flake8)"
	@echo "  format                - Format code (black)"
	@echo "  type-check            - Run type checking (mypy)"
	@echo "  security-check        - Run security checks (bandit, safety)"
	@echo "  quality-check         - Run all quality checks"
	@echo ""
	@echo "Docker:"
	@echo "  build                 - Build Docker images"
	@echo "  run                   - Start services with Docker Compose"
	@echo "  run-postgres          - Start services with PostgreSQL"
	@echo "  run-monitoring        - Start services with monitoring"
	@echo "  stop                  - Stop all services"
	@echo "  logs                  - View service logs"
	@echo "  shell                 - Open shell in DNS server container"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean                 - Clean up generated files"
	@echo "  clean-docker          - Clean up Docker resources"
	@echo "  clean-all             - Clean everything"

# Setup targets
setup: setup-venv install
	@echo "Development environment setup complete!"

setup-dev: setup-venv install-dev setup-pre-commit
	@echo "Full development environment setup complete!"

setup-venv:
	@echo "Setting up virtual environments..."
	cd dns-server && python3 -m venv venv
	cd dns-client && python3 -m venv venv

install:
	@echo "Installing production dependencies..."
	cd dns-server && . venv/bin/activate && pip install -r requirements.txt
	cd dns-client && . venv/bin/activate && pip install -r requirements.txt

install-dev:
	@echo "Installing development dependencies..."
	cd dns-server && . venv/bin/activate && pip install -r requirements.txt -r requirements-dev.txt
	cd dns-client && . venv/bin/activate && pip install -r requirements.txt -r requirements-dev.txt

setup-pre-commit:
	@echo "Setting up pre-commit hooks..."
	cd dns-server && . venv/bin/activate && pre-commit install

# Testing targets
test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	cd dns-server && . venv/bin/activate && pytest tests/ -m "unit or not slow" -v

test-integration:
	@echo "Running integration tests..."
	cd dns-server && . venv/bin/activate && pytest tests/ -m "integration" -v

test-security:
	@echo "Running security tests..."
	cd dns-server && . venv/bin/activate && pytest tests/ -m "security" -v

test-performance:
	@echo "Running performance tests..."
	cd dns-server && . venv/bin/activate && pytest tests/ -m "performance" -v

test-coverage:
	@echo "Running tests with coverage..."
	cd dns-server && . venv/bin/activate && \
		pytest tests/ --cov=bins --cov-report=html --cov-report=term-missing

test-load:
	@echo "Running load tests..."
	docker-compose --profile load-test up load-tester

# Code quality targets
lint:
	@echo "Running linting..."
	cd dns-server && . venv/bin/activate && flake8 bins/ tests/
	cd dns-client && . venv/bin/activate && flake8 bins/ tests/

format:
	@echo "Formatting code..."
	cd dns-server && . venv/bin/activate && black bins/ tests/
	cd dns-client && . venv/bin/activate && black bins/ tests/

type-check:
	@echo "Running type checks..."
	cd dns-server && . venv/bin/activate && mypy bins/
	cd dns-client && . venv/bin/activate && mypy bins/

security-check:
	@echo "Running security checks..."
	cd dns-server && . venv/bin/activate && \
		bandit -r bins/ -f json -o bandit-report.json && \
		safety check --json --output safety-report.json

quality-check: lint format type-check security-check
	@echo "All quality checks completed!"

# Docker targets
build:
	@echo "Building Docker images..."
	docker-compose build

run:
	@echo "Starting Squawk DNS services..."
	docker-compose up -d dns-server dns-client
	@echo "Services started!"
	@echo "DNS Server: http://localhost:8080"
	@echo "Web Console: http://localhost:8000/dns_console"
	@echo "DNS Client: localhost:5353"

run-postgres:
	@echo "Starting Squawk DNS services with PostgreSQL..."
	docker-compose --profile postgres up -d
	@echo "Services started!"
	@echo "DNS Server (SQLite): http://localhost:8080"
	@echo "DNS Server (PostgreSQL): http://localhost:8081"
	@echo "PostgreSQL: localhost:5432"

run-monitoring:
	@echo "Starting Squawk DNS services with monitoring..."
	docker-compose --profile monitoring up -d
	@echo "Services started!"
	@echo "DNS Server: http://localhost:8080"
	@echo "Prometheus: http://localhost:9090"
	@echo "Grafana: http://localhost:3000 (admin/admin123)"

run-test:
	@echo "Running test suite in Docker..."
	docker-compose --profile testing up test-runner

stop:
	@echo "Stopping all services..."
	docker-compose down

logs:
	@echo "Following service logs..."
	docker-compose logs -f

shell:
	@echo "Opening shell in DNS server container..."
	docker-compose exec dns-server /bin/bash

# Cleanup targets
clean:
	@echo "Cleaning up generated files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "coverage.xml" -delete
	find . -type f -name "bandit-report.json" -delete
	find . -type f -name "safety-report.json" -delete
	find . -type f -name "*.log" -delete

clean-docker:
	@echo "Cleaning up Docker resources..."
	docker-compose down -v --remove-orphans
	docker system prune -f
	docker volume prune -f

clean-all: clean clean-docker
	@echo "Full cleanup completed!"

# Development shortcuts
dev: setup-dev run
	@echo "Development environment ready!"

test-all: quality-check test test-load
	@echo "All tests completed!"

# Status check
status:
	@echo "Checking service status..."
	docker-compose ps
	@echo ""
	@echo "Health checks:"
	@curl -f http://localhost:8080/health 2>/dev/null && echo "✓ DNS Server healthy" || echo "✗ DNS Server unhealthy"
	@curl -f http://localhost:8000/dns_console/ 2>/dev/null && echo "✓ Web Console healthy" || echo "✗ Web Console unhealthy"

# Quick deployment verification
verify:
	@echo "Verifying deployment..."
	@echo "Testing DNS query with development token..."
	@curl -H "Authorization: Bearer test-token-for-development" \
		"http://localhost:8080/dns-query?name=example.com&type=A" 2>/dev/null \
		| python3 -m json.tool || echo "DNS query failed"
	@echo ""
	@echo "Testing Web Console API..."
	@curl "http://localhost:8000/dns_console/api/validate/test-token-for-development" 2>/dev/null \
		| python3 -m json.tool || echo "Console API failed"