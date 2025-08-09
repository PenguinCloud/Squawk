# Unified Multi-stage Dockerfile for Squawk DNS System
# Python 3.13 - Standardized Build Environment
FROM python:3.13-slim AS base

LABEL company="Penguin Tech Group LLC"
LABEL org.opencontainers.image.authors="info@penguintech.group"
LABEL license="GNU AGPL3"
LABEL description="Squawk DNS-over-HTTPS System - Unified Server and Client Build"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install basic build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libc6-dev \
    libffi-dev \
    libssl-dev \
    pkg-config \
    build-essential \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install LDAP and XML dependencies
RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libxslt1-dev \
    libldap-dev \
    libldap2-dev \
    libsasl2-dev \
    libldap-common \
    dnsutils \
    net-tools \
    procps \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Create directories
RUN mkdir -p /app/dns-server /app/dns-client /app/data /app/logs /app/certs && \
    chown -R appuser:appuser /app

WORKDIR /app

# DNS Server Stage
FROM base AS dns-server

# Copy requirements files
COPY dns-server/requirements*.txt /app/dns-server/

# Install Python dependencies with fallback for enterprise features
RUN pip install --upgrade pip wheel setuptools && \
    if [ -f /app/dns-server/requirements-base.txt ]; then \
        echo "Installing with fallback strategy..." && \
        (pip install -r /app/dns-server/requirements.txt 2>/dev/null && echo "Full installation successful") || \
        (echo "WARNING: Enterprise features failed, using base requirements..." && \
         pip install -r /app/dns-server/requirements-base.txt); \
    else \
        echo "Installing all requirements..." && \
        pip install -r /app/dns-server/requirements.txt; \
    fi

# Copy DNS server code
COPY dns-server/ /app/dns-server/
COPY docs/ /app/docs/

# Set permissions
RUN chown -R appuser:appuser /app

USER appuser

# Health check for DNS server
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f "http://localhost:8080/health" || exit 1

EXPOSE 8080 8000

# Default command
CMD ["python", "/app/dns-server/bins/server.py", "-p", "8080", "-n"]

# DNS Client Stage
FROM base AS dns-client

# Create requirements files for client
RUN echo "dnspython>=2.4.2" > /app/dns-client/requirements.txt && \
    echo "requests>=2.31.0" >> /app/dns-client/requirements.txt && \
    echo "PyYAML>=6.0.1" >> /app/dns-client/requirements.txt

RUN echo "pytest>=7.4.3" > /app/dns-client/requirements-dev.txt && \
    echo "pytest-cov>=4.1.0" >> /app/dns-client/requirements-dev.txt && \
    echo "pytest-mock>=3.12.0" >> /app/dns-client/requirements-dev.txt

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r /app/dns-client/requirements.txt

# Copy DNS client code
COPY dns-client/ /app/dns-client/
COPY docs/ /app/docs/

# Set permissions
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 53/udp 53/tcp

# Default command
CMD ["python", "/app/dns-client/bins/client.py", "-u", "-T"]

# Testing Stage
FROM dns-server AS testing

USER root

# Install development dependencies
RUN pip install -r /app/dns-server/requirements-dev.txt

# Install additional testing tools
RUN pip install \
    safety==2.3.5 \
    bandit==1.7.5 \
    pytest-xdist==3.3.1

# Copy test files
COPY dns-server/tests/ /app/dns-server/tests/
COPY dns-client/tests/ /app/dns-client/tests/

# Create test data directory
RUN mkdir -p /app/test-data && chown -R appuser:appuser /app

USER appuser

# Default command for testing
CMD ["pytest", "/app/dns-server/tests/", "/app/dns-client/tests/", "-v", "--cov=/app"]

# Production Stage
FROM dns-server AS production

USER root

# Install production monitoring tools
RUN pip install \
    prometheus-client==0.18.0 \
    structlog==23.1.0

# Set production environment variables
ENV PYTHONPATH=/app \
    SQUAWK_ENV=production \
    SQUAWK_LOG_LEVEL=INFO

USER appuser

# Production health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD curl -f "http://localhost:${SQUAWK_PORT:-8080}/health" || exit 1

# Production command
CMD ["python", "/app/dns-server/bins/server.py", \
     "-p", "${SQUAWK_PORT:-8080}", \
     "-n"]
