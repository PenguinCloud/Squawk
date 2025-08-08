- to memorize
# important-instruction-reminders
Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files. Only create documentation files if explicitly requested by the User.

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