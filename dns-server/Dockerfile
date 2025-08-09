# DNS Server Dockerfile with Python 3.13
FROM python:3.13-slim

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
    TZ=UTC \
    SQUAWK_ENV=${SQUAWK_ENV:-production}

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    libxml2-dev \
    libxslt1-dev \
    libldap2-dev \
    libsasl2-dev \
    libffi-dev \
    libssl-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    pkg-config \
    curl \
    wget \
    dnsutils \
    net-tools \
    procps \
    sqlite3 \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/bash appuser

# Create directories
RUN mkdir -p /app/dns-server /app/data /app/logs /app/certs /app/web && \
    chown -R appuser:appuser /app

WORKDIR /app/dns-server

# Copy requirements files
COPY requirements*.txt ./

# Install Python dependencies
RUN pip install --upgrade pip wheel setuptools && \
    pip install -r requirements.txt && \
    if [ "$SQUAWK_ENV" = "development" ] || [ "$SQUAWK_ENV" = "test" ] || [ -f requirements-dev.txt ]; then \
        echo "Installing development dependencies..." && \
        pip install -r requirements-dev.txt 2>/dev/null || \
        echo "No dev requirements found or installation failed - continuing with production setup"; \
    fi && \
    python -c "import sys; print(f'Python {sys.version}')" && \
    echo "✓ Python dependencies installed successfully"


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

# Smart command selection based on environment
CMD if [ "$SQUAWK_ENV" = "test" ]; then \
        echo "Running tests..." && \
        python -m pytest tests/ -v; \
    else \
        echo "Starting DNS server..." && \
        python /app/dns-server/bins/server.py -p ${PORT:-8080} -n; \
    fi