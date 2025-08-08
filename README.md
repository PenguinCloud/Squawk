[![Publish Docker image](https://github.com/PenguinCloud/project-template/actions/workflows/docker-image.yml/badge.svg)](https://github.com/PenguinCloud/core/actions/workflows/docker-image.yml) [![version](https://img.shields.io/badge/version-5.1.1-blue.svg)](https://semver.org) 

# Squawk - DNS-over-HTTPS Proxy System

Squawk is a secure, scalable DNS-over-HTTPS (DoH) proxy system that provides authenticated DNS resolution services with fine-grained access control. It consists of both server and client components that enable secure DNS queries over HTTPS with token-based authentication and domain-level access restrictions.

## Features

### Core Functionality
- **DNS-over-HTTPS (DoH) Support**: Secure DNS resolution using HTTPS protocol with HTTP/3 support
- **High Performance**: Async architecture supporting thousands of requests per second
- **Token-Based Authentication**: Bearer token authentication for access control
- **Domain Access Control**: Fine-grained permissions allowing specific tokens to access specific domains
- **Local DNS Forwarding**: Client can act as local DNS forwarder on port 53 (UDP/TCP)
- **TLS/SSL Support**: Optional SSL/TLS encryption for enhanced security
- **Database Integration**: Support for persistent token and domain permission storage
- **Web Management Console**: Py4web-based interface for managing tokens and permissions
- **System Tray Integration**: Cross-platform desktop system tray icon for easy management
- **Automatic System Service**: Install as system service/daemon with automatic DNS configuration

### Performance & Caching
- **Valkey/Redis Caching**: High-performance caching with configurable TTL
- **In-Memory Fallback**: Automatic fallback to in-memory cache if Redis/Valkey unavailable
- **Multi-threading Support**: Utilizes multiple workers for optimal performance
- **Async I/O**: Built on asyncio for non-blocking operations
- **HTTP/3 Support**: Latest protocol support for improved performance

### Security Features
- **DNS Blackholing**: Block malicious domains and IPs
- **Maravento Blacklist Integration**: Automatic updates from Maravento blackweb list
- **Custom Blacklists**: Admin-managed domain and IP blocking
- **Domain validation and sanitization**: Prevent DNS injection attacks
- **Token-based access restrictions**: Fine-grained access control
- **Per-domain access control lists**: Granular permission management
- **SSL/TLS support**: Encrypted communications
- **Input validation**: Comprehensive security checks

## Architecture

### Components

1. **DNS Server** (`dns-server/`)
   - HTTP/HTTPS server handling DNS queries
   - Token authentication and validation
   - Domain access control enforcement
   - Database integration for token management
   - Web console for administration

2. **DNS Client** (`dns-client/`)
   - DNS-over-HTTPS client
   - Local DNS forwarding capabilities (port 53)
   - Support for both UDP and TCP
   - Kubernetes integration support
   - Configuration file support

3. **Web Console** (`web/`)
   - Py4web-based administration interface
   - Token management
   - Domain permission configuration
   - Real-time monitoring and logging

## Installation

### Quick Install (Recommended)

The easiest way to install Squawk is using the automated installer:

```bash
# Install with default settings
sudo python3 install.py install

# Install with custom server
sudo SQUAWK_SERVER_URL=https://dns.example.com SQUAWK_AUTH_TOKEN=your-token python3 install.py install

# Uninstall
sudo python3 install.py uninstall
```

The installer will:
- Install all dependencies
- Set up Squawk as a system service/daemon
- Configure your system DNS to use Squawk
- Create a system tray icon (on desktop systems)
- Start the service automatically

### Using Docker

```bash
docker-compose up -d
```

### Manual Installation

#### Server Setup

```bash
cd dns-server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Standard server
python bins/server.py -p 8080

# Optimized server with caching and blacklist support
ENABLE_BLACKLIST=true VALKEY_URL=redis://localhost:6379 python bins/server_optimized.py -p 8080
```

#### Client Setup

```bash
cd dns-client
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# CLI usage
python bins/client.py -d example.com -s http://localhost:8080

# System tray application
python bins/systray.py -c config.yaml
```

## Configuration

### Environment Variables

All configuration is done via environment variables:

#### Server Configuration
- `PORT`: Server port (default: 8080)
- `MAX_WORKERS`: Number of worker processes (default: 100)
- `MAX_CONCURRENT_REQUESTS`: Max concurrent DNS requests (default: 1000)
- `AUTH_TOKEN`: Legacy authentication token
- `USE_NEW_AUTH`: Enable new token management system (true/false)
- `DB_TYPE`: Database type for auth
- `DB_URL`: Database connection URL

#### Cache Configuration
- `CACHE_ENABLED`: Enable caching (default: true)
- `CACHE_TTL`: Cache TTL in seconds (default: 300)
- `VALKEY_URL` or `REDIS_URL`: Valkey/Redis connection URL (e.g., redis://localhost:6379)
- `CACHE_PREFIX`: Cache key prefix (default: squawk:dns:)

#### Blacklist Configuration
- `ENABLE_BLACKLIST`: Enable Maravento blacklist (default: false)
- `BLACKLIST_UPDATE_HOURS`: Update interval in hours (default: 24)

#### Client Configuration
- `SQUAWK_SERVER_URL`: DNS server URL (default: https://dns.google/resolve)
- `SQUAWK_AUTH_TOKEN`: Authentication token
- `SQUAWK_CONSOLE_URL`: Admin console URL (default: http://localhost:8080/dns_console)
- `LOG_LEVEL`: Logging level (default: INFO)

### Server Configuration

The server accepts the following command-line arguments:

```bash
python server_optimized.py [options]
  -t, --token <token>   : Authentication token for API access
  -p, --port <port>     : Port to listen on (default: 8080)
  -k, --key <keyfile>   : SSL key file path
  -c, --cert <certfile> : SSL certificate file path
  -d, --dbtype <type>   : Database type (sqlite, postgres, mysql)
  -u, --dburl <url>     : Database connection URL
  -n, --newauth         : Use new token management system
```

Example with all features:
```bash
ENABLE_BLACKLIST=true VALKEY_URL=redis://localhost:6379 CACHE_TTL=600 \
python server_optimized.py -p 8443 -k server.key -c server.crt -n
```

### Client Configuration

The client accepts the following command-line arguments:

```bash
python client.py [options]
  -d, --domain <domain>    : Domain to query
  -t, --type <type>        : DNS record type (default: A)
  -s, --server <url>       : DNS server URL
  -a, --auth <token>       : Authentication token
  -c, --config <file>      : Configuration file path
  -u, --udp                : Enable UDP forwarding on port 53
  -T, --tcp                : Enable TCP forwarding on port 53
```

Example with authentication:
```bash
python client.py -d example.com -s https://dns.example.com:8443 -a your-token-here
```

### Configuration File Format

The client supports YAML configuration files:

```yaml
domain: example.com
type: A
server: https://dns.example.com:8443
auth: your-token-here
```

## Token Management

### Database Schema

The system uses a simple database schema for token management:

```sql
CREATE TABLE auth (
    id INTEGER PRIMARY KEY,
    token VARCHAR(255) NOT NULL,
    domain TEXT NOT NULL
);
```

### Domain Permissions

Tokens can be assigned to specific domains:
- Use `*` for wildcard (access to all domains)
- Use comma-separated list for multiple domains: `example.com,test.com`
- Domains are validated against a regex pattern for security

## API Endpoints

### DNS Query Endpoint

```
GET /dns-query?name=<domain>&type=<record_type>
Headers:
  Authorization: Bearer <token>
```

Response format:
```json
{
  "Status": 0,
  "Answer": [
    {
      "name": "example.com",
      "data": "93.184.216.34"
    }
  ]
}
```

## Web Console

The py4web-based console provides:

- **Token Management**: Create, update, delete authentication tokens
- **Domain Permissions**: Assign domains to tokens with granular control
- **Blacklist Management**: Manage blocked domains and IPs
- **Activity Monitoring**: View DNS query logs and statistics
- **System Configuration**: Manage server settings and parameters
- **Cache Statistics**: Monitor cache performance and hit rates
- **Health Monitoring**: Real-time system health and performance metrics

Access the console at: `http://localhost:8080/dns_console`

### Admin Features

- **DNS Blackholing**: Block malicious domains at DNS level
- **Maravento Integration**: Automatic updates from Maravento blackweb list
- **Custom Blacklists**: Add/remove domains and IPs manually
- **Real-time Updates**: Changes take effect immediately without restart

## Security Considerations

1. **Always use TLS/SSL** in production environments
2. **Rotate tokens regularly** to maintain security
3. **Implement rate limiting** to prevent abuse
4. **Monitor logs** for suspicious activity
5. **Use strong, random tokens** for authentication
6. **Validate all input** to prevent injection attacks
7. **Keep the system updated** with security patches

## Development

### Project Structure

```
Squawk/
├── dns-server/          # Server component
│   ├── bins/            # Executable scripts
│   ├── web/             # Py4web application
│   └── tests/           # Unit tests
├── dns-client/          # Client component
│   ├── bins/            # Executable scripts
│   └── tests/           # Unit tests
├── docs/                # Documentation
├── docker-compose.yml   # Docker configuration
└── README.md           # This file
```

### Running Tests

```bash
# All tests
pytest

# Server tests
cd dns-server
python tests/unittests.py

# Client tests
cd dns-client
python tests/unittests.py

# New feature tests
pytest tests/test_blacklist.py
pytest tests/test_cache.py
pytest tests/test_installer.py
```

### Performance Testing

```bash
# Load testing with k6
k6 run tests/load-test.js

# Benchmark caching
CACHE_ENABLED=true VALKEY_URL=redis://localhost:6379 python tests/benchmark_cache.py
```

## Why Squawk?

### Built-in Security
- Token-based authentication out of the box
- Domain-level access control
- TLS/SSL support for encrypted communications
- Input validation and sanitization

### Scalability
- Microservices architecture
- Horizontal scaling support
- Database backend for persistent storage
- Lightweight and efficient

### Flexibility
- Multiple deployment options (Docker, standalone, Kubernetes)
- Configurable authentication methods
- Support for various database backends
- Extensible architecture

### Active Development
- Regular updates and security patches
- Community-driven development
- Professional support available

## Contributors

### PTG
- Maintainer: creatorsemailhere@penguintech.group
- General: info@penguintech.group

### Community
- Contributions welcome! Please see CONTRIBUTING.md

## Resources

- Documentation: `./docs/`
- Premium Support: https://support.penguintech.group
- Community Issues: [GitHub Issues](https://github.com/PenguinCloud/Squawk/issues)

## License

See LICENSE.md in the docs folder for licensing information.

## Roadmap

- [ ] Enhanced Web UI with real-time monitoring
- [ ] Support for additional DNS record types
- [ ] Advanced caching mechanisms
- [ ] Multi-factor authentication support
- [ ] API rate limiting
- [ ] Prometheus metrics integration
- [ ] GraphQL API support
- [ ] DNS-over-TLS (DoT) support