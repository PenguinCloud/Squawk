# DNS Server Dockerfile using Ubuntu LTS
FROM ubuntu:22.04

LABEL company="Penguin Tech Group LLC"
LABEL org.opencontainers.image.authors="info@penguintech.group"
LABEL license="GNU AGPL3"
LABEL description="Squawk DNS-over-HTTPS Server with Enterprise Features"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    build-essential \
    gcc \
    g++ \
    libxml2-dev \
    libxslt1-dev \
    libldap-dev \
    libldap2-dev \
    libsasl2-dev \
    libffi-dev \
    libssl-dev \
    pkg-config \
    curl \
    wget \
    dnsutils \
    net-tools \
    procps \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/bash appuser

# Create directories
RUN mkdir -p /app/dns-server /app/data /app/logs /app/certs /app/web && \
    chown -R appuser:appuser /app

WORKDIR /app/dns-server

# Copy requirements files
COPY requirements*.txt ./

# Install Python dependencies with fallback for enterprise features
RUN python3 -m pip install --upgrade pip wheel setuptools && \
    if [ -f requirements-base.txt ]; then \
        echo "Installing with fallback strategy..." && \
        (python3 -m pip install -r requirements.txt 2>/dev/null && \
         echo "✓ Full installation successful with enterprise features") || \
        (echo "⚠ Enterprise features failed, using base requirements..." && \
         python3 -m pip install -r requirements-base.txt && \
         echo "✓ Base installation successful (no LDAP/SAML support)"); \
    else \
        echo "Installing all requirements..." && \
        python3 -m pip install -r requirements.txt; \
    fi

# Copy application code
COPY . /app/dns-server/

# Copy web console
COPY web/ /app/web/

# Set permissions
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f "http://localhost:${PORT:-8080}/health" || exit 1

# Expose ports
EXPOSE 8080 8000

# Default command - start both DNS server and web console
CMD ["sh", "-c", "python3 /app/dns-server/bins/server.py -p ${PORT:-8080} -n"]