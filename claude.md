# Squawk Project Context for Claude

## Project Overview
Squawk is a DNS-over-HTTPS (DoH) proxy system with authentication and access control. It provides secure DNS resolution with token-based authentication and fine-grained domain access permissions.

## Key Components

### DNS Server (`dns-server/bins/server.py`)
- **Purpose**: HTTP/HTTPS server that handles DNS queries with authentication
- **Key Features**:
  - Bearer token authentication
  - Domain access control (tokens can be restricted to specific domains)
  - Database integration for token storage
  - SSL/TLS support
  - Domain validation and sanitization
- **Database Schema**: Simple `auth` table with `token` and `domain` fields
- **Port**: Default 8080, configurable
- **Dependencies**: socketserver, requests, dns.resolver, pydal, ssl

### DNS Client (`dns-client/bins/client.py`)
- **Purpose**: DNS-over-HTTPS client with local forwarding capabilities
- **Key Features**:
  - Query DNS servers over HTTPS
  - Local DNS forwarding on port 53 (UDP/TCP)
  - YAML configuration file support
  - Bearer token authentication support
  - Kubernetes integration ready (`k8s-client.py`)
- **Dependencies**: requests, socket, threading, yaml

### Web Framework
- **Py4web**: Already installed in both client and server virtual environments
- **Location**: `web/apps/` directories
- **Scaffold App**: Template application ready for customization
- **Database**: PyDAL ORM included for database operations

## Current Authentication Model
- Single token per server/client setup
- Tokens stored in database with comma-separated domain lists
- Domain validation using regex patterns
- Wildcard support (`*` for all domains)

## Proposed Enhancement: Multi-Token Domain Access Control

### Requirements
1. Multiple tokens can be created and managed
2. Each token has specific domain permissions
3. Tokens can share access to common domains
4. Example:
   - Token A: Can access domains A, C (not B)
   - Token B: Can access domains B, C, D

### Implementation Strategy
1. **Enhanced Database Schema**:
   - `tokens` table: id, token, name, created_at, last_used
   - `domains` table: id, name, description
   - `token_domains` table: token_id, domain_id (many-to-many)

2. **Py4web Console Features**:
   - Token CRUD operations
   - Domain management
   - Permission matrix UI
   - Activity logging
   - Usage statistics

3. **API Endpoints**:
   - `/api/tokens` - Manage tokens
   - `/api/domains` - Manage domains
   - `/api/permissions` - Manage token-domain associations
   - `/api/logs` - View activity logs

## Technical Notes

### Security Considerations
- Input validation is critical (domain regex already implemented)
- Tokens should be cryptographically secure
- Consider rate limiting for API endpoints
- Log all authentication attempts
- SSL/TLS should be mandatory in production

### Performance Considerations
- Token validation happens on every request
- Consider caching token-domain mappings
- Database queries should be optimized
- Connection pooling for database

### Testing
- Unit tests exist in `tests/unittests.py`
- Need to add tests for new token management features
- Integration tests for py4web console
- Load testing for concurrent token validation

## File Structure Patterns
- Binary executables in `bins/`
- Web applications in `web/apps/`
- Libraries in `libs/`
- Tests in `tests/`
- Configuration in `vars/`
- Templates in `templates/`

## Development Workflow
1. Virtual environments are already set up in `venv/` directories
2. Py4web is installed and ready
3. PyDAL is available for database operations
4. Use existing scaffold app as template

## Known Limitations
- DNS response creation in client is incomplete (line 84 in client.py)
- Domain extraction from DNS request needs implementation (line 81 in client.py)
- Current token system is single-token only
- No web UI exists yet for token management

## Next Steps for Implementation
1. Create enhanced database schema
2. Build py4web application for token management
3. Modify server.py to support multi-token lookups
4. Add API endpoints for token/domain management
5. Create web UI with permission matrix
6. Add logging and monitoring capabilities
7. Write comprehensive tests

## Important Files to Modify
- `/dns-server/bins/server.py` - Update token validation logic
- `/dns-server/web/apps/` - Create new py4web app for console
- Database migrations needed for new schema
- API documentation to be created

## Commands and Execution
- Server: `python dns-server/bins/server.py -p 8080 -d sqlite -u auth.db`
- Client: `python dns-client/bins/client.py -d example.com -s http://localhost:8080 -a TOKEN`
- Py4web: `py4web run apps` (from web directory)

## Environment Details
- Python 3.12 in virtual environments
- Py4web 1.20250215.1 installed
- PyDAL 20250215.2 installed
- DNS resolver library available
- Git repository on v1.1 branch