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
- `SQUAWK_CONSOLE_URL`: Admin console URL (default: http://localhost:8080/dns_console)
- `LOG_LEVEL`: Logging level (default: INFO)