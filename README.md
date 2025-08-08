[![Publish Docker image](https://github.com/PenguinCloud/project-template/actions/workflows/docker-image.yml/badge.svg)](https://github.com/PenguinCloud/core/actions/workflows/docker-image.yml) [![version](https://img.shields.io/badge/version-5.1.1-blue.svg)](https://semver.org) 

# Squawk - DNS-over-HTTPS Proxy System

Squawk is a secure, scalable DNS-over-HTTPS (DoH) proxy system that provides authenticated DNS resolution services with fine-grained access control. It consists of both server and client components that enable secure DNS queries over HTTPS with token-based authentication and domain-level access restrictions.

## Features

### Core Functionality
- **DNS-over-HTTPS (DoH) Support**: Secure DNS resolution using HTTPS protocol
- **Token-Based Authentication**: Bearer token authentication for access control
- **Domain Access Control**: Fine-grained permissions allowing specific tokens to access specific domains
- **Local DNS Forwarding**: Client can act as local DNS forwarder on port 53 (UDP/TCP)
- **TLS/SSL Support**: Optional SSL/TLS encryption for enhanced security
- **Database Integration**: Support for persistent token and domain permission storage
- **Web Management Console**: Py4web-based interface for managing tokens and permissions

### Security Features
- Domain validation and sanitization
- Token-based access restrictions
- Per-domain access control lists
- SSL/TLS support for encrypted communications
- Input validation to prevent DNS injection attacks

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
python bins/server.py -p 8080
```

#### Client Setup

```bash
cd dns-client
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python bins/client.py -d example.com -s http://localhost:8080
```

## Configuration

### Server Configuration

The server accepts the following command-line arguments:

```bash
python server.py [options]
  -a, --auth <token>    : Authentication token for API access
  -p, --port <port>     : Port to listen on (default: 8080)
  -k, --key <keyfile>   : SSL key file path
  -c, --cert <certfile> : SSL certificate file path
  -d, --dbtype <type>   : Database type (sqlite, postgres, mysql)
  -u, --dburl <url>     : Database connection URL
```

Example with database and SSL:
```bash
python server.py -p 8443 -k server.key -c server.crt -d sqlite -u dns_auth.db
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
- **Activity Monitoring**: View DNS query logs and statistics
- **System Configuration**: Manage server settings and parameters

Access the console at: `http://localhost:8080/_scaffold`

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
# Server tests
cd dns-server
python tests/unittests.py

# Client tests
cd dns-client
python tests/unittests.py
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