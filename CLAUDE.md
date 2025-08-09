- to memorize
# important-instruction-reminders
Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files. Only create documentation files if explicitly requested by the User.

# Python Version Standard
ALL Python-based builds and deployments MUST use Python 3.13. This includes:
- Dockerfiles
- CI/CD workflows
- Requirements files
- Local development environments

# Docker Container Architecture
Each Python component is built as its own separate Docker container image:
- DNS Server: Separate container with server-specific dependencies
- DNS Client (Python): Separate container with client-specific dependencies
- Testing Environment: Separate container with development/testing tools
- Production Environment: Separate optimized container for production deployments

# Docker Base Image Standard
ALL Docker containers MUST use Ubuntu 24.04 LTS as the base image with Python 3.13 from deadsnakes PPA.
This is REQUIRED because:
- python-ldap compilation requires lber.h header which is missing in Debian-based images
- Ubuntu provides proper LDAP development packages (libldap-dev, libldap2-dev, libsasl2-dev)
- deadsnakes PPA provides reliable Python 3.13 installation on Ubuntu
- DO NOT use python:3.13-slim or other Debian-based images due to LDAP header issues

# Environment Variable Configuration
ALL user configuration for Squawk DNS is done via environment variables:

## Server Configuration
- `PORT`: Server port (default: 8080)
- `MAX_WORKERS`: Number of worker processes (default: 100)
- `MAX_CONCURRENT_REQUESTS`: Max concurrent DNS requests (default: 1000)
- `AUTH_TOKEN`: Legacy authentication token
- `USE_NEW_AUTH`: Enable new token management system (true/false)
- `DB_TYPE`: Database type for auth
- `DB_URL`: Database connection URL

## Cache Configuration
- `CACHE_ENABLED`: Enable caching (default: true)
- `CACHE_TTL`: Cache TTL in seconds (default: 300)
- `VALKEY_URL` or `REDIS_URL`: Valkey/Redis connection URL (e.g., redis://localhost:6379)
- `CACHE_PREFIX`: Cache key prefix (default: squawk:dns:)

## Blacklist Configuration
- `ENABLE_BLACKLIST`: Enable Maravento blacklist (default: false)
- `BLACKLIST_UPDATE_HOURS`: Update interval in hours (default: 24)

## Client Configuration
- `SQUAWK_SERVER_URL`: DNS server URL (default: https://dns.google/resolve)
- `SQUAWK_AUTH_TOKEN`: Authentication token
- `SQUAWK_DOMAIN`: Default domain to query
- `SQUAWK_RECORD_TYPE`: Default DNS record type (default: A)
- `SQUAWK_CLIENT_CERT`: Client certificate path for mTLS
- `SQUAWK_CLIENT_KEY`: Client private key path for mTLS
- `SQUAWK_CA_CERT`: CA certificate path for verification
- `SQUAWK_VERIFY_SSL`: Enable SSL verification (true/false)
- `SQUAWK_CONSOLE_URL`: Admin console URL (default: http://localhost:8080/dns_console)
- `LOG_LEVEL`: Logging level (default: INFO)

## Logging Configuration
- `LOG_LEVEL`: Logging level - DEBUG, INFO, WARNING, ERROR (default: INFO)
- `LOG_FORMAT`: Log format - json or text (default: json)
- `LOG_FILE`: Log file path (optional)
- `TRUSTED_PROXIES`: Comma-separated trusted proxy IP ranges (default: 127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)

## Syslog Configuration
- `ENABLE_SYSLOG`: Enable UDP syslog forwarding (default: false)
- `SYSLOG_HOST`: Syslog server hostname/IP (default: localhost)
- `SYSLOG_PORT`: Syslog server port (default: 514)
- `SYSLOG_FACILITY`: Syslog facility number (default: 16)

## mTLS Configuration
- `ENABLE_MTLS`: Enable mutual TLS authentication (default: false)
- `MTLS_ENFORCE`: Require client certificates (default: false)
- `MTLS_CA_CERT`: CA certificate path for client verification (default: certs/ca.crt)
- `CERT_DIR`: Certificate storage directory (default: certs)

## TLS Certificate Configuration
- `USE_ECC_KEYS`: Use ECC keys instead of RSA (default: true)
- `ECC_CURVE`: ECC curve to use - SECP256R1, SECP384R1, SECP521R1 (default: SECP384R1)
- `CA_VALIDITY_DAYS`: CA certificate validity period (default: 3650)
- `CERT_VALIDITY_DAYS`: Server/client certificate validity (default: 365)
- `TLS_ADDITIONAL_HOSTS`: Additional hostnames for server cert (comma-separated)
- `CLIENT_CERT_PATH`: Client certificate path for mTLS
- `CLIENT_KEY_PATH`: Client private key path for mTLS
- `CA_CERT_PATH`: CA certificate path for verification

Note: ECC certificates provide equivalent security to RSA with smaller key sizes and better performance.

# System Tray Client Configuration
The desktop system tray application (dns-client/bins/systray.py) provides enhanced functionality:

## System Tray Features
- **Health Monitoring**: Real-time DNS server health checks every 30 seconds
- **Visual Health Status**: Icon colors indicate server health (green=healthy, yellow=degraded, red=unhealthy)
- **Smart Notifications**: Automatic alerts when DNS servers become unreachable
- **DNS Fallback**: One-click fallback to original DHCP DNS servers for captive portals
- **Manual Health Check**: On-demand server connectivity verification

## DNS Fallback System
- Automatically detects original DNS servers from system configuration
- Supports Windows, macOS, and Linux platforms
- Essential for hotel/airport WiFi captive portals
- Restores DNS settings on application exit

# Release Automation
Automated GitHub CI/CD release pipeline with comprehensive release notes:

## Release Notes Integration
- **Script**: `.github/scripts/extract-release-notes.sh`
- **Source**: `docs/RELEASE_NOTES.md` 
- **Automation**: Both client and server releases automatically include full release notes
- **Components**: Separate release processes for Go client (-client) and DNS server (-server)

## Release Process
1. Version updates in `.version` file trigger releases
2. Automatic extraction of release notes from documentation
3. Component-specific quick start guides included
4. Platform-specific installation instructions
5. GitHub releases created with comprehensive documentation

# Important Notes
- **Documentation Domain**: All documentation references should use `squawkdns.com`
- **Web Console**: Default available at `http://localhost:8000/dns_console`
- **Health Monitoring**: System tray provides real-time server health status
- **DNS Validation**: All components implement RFC 1035 compliant validation
- **Multi-Server Support**: Clients support multiple DNS servers with automatic failover

# Git Workflow
ALWAYS commit all changes when completing work or making significant modifications to ensure proper version control and deployment tracking.