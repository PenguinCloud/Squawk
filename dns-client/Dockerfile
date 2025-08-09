# DNS Client Dockerfile with Python 3.13
FROM ubuntu:24.04

LABEL company="Penguin Tech Group LLC"
LABEL org.opencontainers.image.authors="info@penguintech.group"
LABEL license="GNU AGPL3"
LABEL description="Squawk DNS Client - DNS-over-HTTPS Forwarder"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# Install system dependencies and Python 3.13
RUN apt-get update && apt-get install -y \
    software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y \
    python3.13 \
    python3.13-pip \
    python3.13-dev \
    python3.13-venv \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    curl \
    wget \
    dnsutils \
    net-tools \
    procps \
    ca-certificates \
    systemd \
    && ln -sf /usr/bin/python3.13 /usr/bin/python3 \
    && ln -sf /usr/bin/python3.13 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/bash appuser

# Create directories
RUN mkdir -p /app/dns-client /app/data /app/logs /app/certs && \
    chown -R appuser:appuser /app

WORKDIR /app/dns-client

# Copy requirements file
COPY requirements.txt ./

# Install Python dependencies
RUN python3.13 -m pip install --upgrade pip wheel setuptools && \
    python3.13 -m pip install -r requirements.txt

# Copy application code
COPY . /app/dns-client/

# Set permissions
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import dns.resolver; r = dns.resolver.Resolver(); r.nameservers = ['127.0.0.1']; r.query('health.check', 'A')" 2>/dev/null || exit 1

# Expose DNS ports
EXPOSE 53/udp 53/tcp

# Environment variables for configuration
ENV SQUAWK_SERVER_URL=https://dns.google/resolve \
    SQUAWK_AUTH_TOKEN="" \
    SQUAWK_DOMAIN="" \
    SQUAWK_RECORD_TYPE=A \
    LOG_LEVEL=INFO

# Default command - DNS forwarder mode
CMD ["python3", "/app/dns-client/bins/client.py", "-s", "${SQUAWK_SERVER_URL}", "-a", "${SQUAWK_AUTH_TOKEN}", "-u", "-T", "-v"]