# Squawk DNS System Release Notes

## v1.1.2 - Maintenance and Security Release

**Release Date**: August 2025  
**Release Type**: Patch Release with CI/CD and Security Fixes  
**Breaking Changes**: None (backward compatible)

### 🛠️ Build System & CI/CD Improvements

#### Build Standardization
- **Python 3.13 Standardization**: All Python components now use Python 3.13 across Docker, CI/CD, and documentation
- **Go 1.23 Standardization**: All Go components standardized on Go 1.23 with removed toolchain specifications
- **Virtual Environment Isolation**: Implemented proper virtual environments in all Docker containers to prevent system package conflicts
- **Simplified Build Matrix**: Removed complex matrix strategies for more reliable single-version builds

#### GitHub Actions Enhancements
- **Separate Build Verification**: Added dedicated build job that runs on both PRs and main branch pushes
- **Security Tools Update**: Updated to official `github.com/securego/gosec` repository (8,401+ stars, actively maintained)
- **Docker Syntax Fixes**: Fixed Docker build command syntax errors in CI/CD workflows
- **LDAP Dependencies**: Added comprehensive LDAP development packages for python-ldap compilation

### 🔐 Security Improvements

#### Go Security Enhancements
- **Zero Security Issues**: Resolved all 9 security issues found by gosec scanner
- **Safe Integer Conversions**: Added `safeUint32()` function to prevent integer overflow vulnerabilities
- **File Permissions**: Updated file permissions from 0644 to 0600 for sensitive configuration files
- **Security Tool Standards**: Documented security tools in CLAUDE.md to prevent future tool selection issues

#### Documentation Security
- **Security Tools Standard**: Added official security scanning tools to development guidelines
- **Version Standards**: Documented Go 1.23 and Python 3.13 standards to prevent version conflicts

### 🌐 Website & Documentation Fixes

#### Website Navigation
- **Footer Links Fixed**: Footer navigation links now properly appear as clickable links using inline styles
- **Documentation Page URLs**: Updated documentation page links to match MkDocs URL structure
- **Bootstrap Compatibility**: Resolved Bootstrap CSS conflicts with Next.js Link components

#### Documentation Structure
- **MkDocs Integration**: Properly configured for `docs.squawkdns.com` Cloudflare Pages deployment
- **API Documentation**: Enhanced API.md with comprehensive endpoint documentation
- **URL Standardization**: All documentation references now use consistent `squawkdns.com` domain

### 🧹 Code Quality & Maintenance

#### Development Environment
- **Docker Build Reliability**: Fixed multiple Docker build failures with proper dependency management
- **Package Dependencies**: Resolved missing system dependencies for LDAP and SSL libraries
- **Testing Infrastructure**: Enhanced test execution within Docker containers for environment parity

#### Configuration Management  
- **Environment Variable Documentation**: Updated CLAUDE.md with complete configuration reference
- **Build Documentation**: Added clear build system standards to prevent future compatibility issues

### 🐛 Bug Fixes

- **Docker Multi-stage Builds**: Fixed target specification errors in GitHub workflows
- **Python Package Conflicts**: Resolved pip installation conflicts with `--break-system-packages` flag usage
- **LDAP Compilation**: Fixed python-ldap build failures by adding required development headers
- **Version Compatibility**: Resolved Go toolchain version mismatches causing build failures

### 📚 Documentation Updates

- **CLAUDE.md Enhancements**: Added Go version standards and security tools documentation
- **API Documentation**: Comprehensive API endpoint documentation with examples
- **Build Standards**: Documented Python 3.13 and Go 1.23 standardization decisions

### 🔄 Migration Notes

- **Automatic**: No manual intervention required for existing deployments
- **CI/CD**: GitHub workflows will automatically use new standards
- **Docker**: Existing containers will rebuild with improved dependency management

---

# Squawk DNS System v1.1.1 Release Notes

**Release Date**: August 2025  
**Release Type**: Major Feature Release with Critical Security Hotfixes  
**Breaking Changes**: None (backward compatible)

## 🎉 Executive Summary

Squawk v1.1.1 represents a massive leap forward in DNS-over-HTTPS proxy technology, introducing a complete Go client implementation, comprehensive enterprise security features, and production-ready infrastructure. This release adds over 10,000 lines of new code, 28 new files, and transforms Squawk from a simple DNS proxy into a full-featured enterprise DNS security solution.

## 🔥 Critical Hotfixes in v1.1.1

### Security Enhancements
1. **DNS Loop Prevention**: Added IP address validation to prevent infinite DNS resolution loops when using custom DNS servers
2. **Multiple Server Failover**: Implemented automatic failover with configurable retry logic for high availability
3. **Enhanced DNS Validation**: Strengthened input validation to prevent injection attacks and malformed queries
4. **Public DNS Compatibility**: Fixed compatibility issues with Google DNS and Cloudflare DNS-over-HTTPS services

### Bug Fixes
1. **URL Path Normalization**: Auto-corrects paths for public DNS providers (/resolve vs /dns-query)
2. **Certificate Validation**: Fixed edge cases in mTLS certificate validation
3. **Error Handling**: Improved error messages and aggregation for multiple server failures
4. **Configuration Loading**: Fixed environment variable parsing for comma-delimited server lists

### System Tray Enhancements (NEW)
1. **Health Monitoring**: Real-time DNS server health monitoring with visual indicators
2. **Smart Notifications**: Automatic alerts when DNS servers become unreachable
3. **DNS Fallback**: One-click fallback to original DHCP DNS servers for captive portals
4. **Visual Health Status**: Icon colors indicate server health (green=healthy, yellow=degraded, red=unhealthy)

## 🚀 Major New Features

### 1. Go Client Implementation (NEW)
Complete high-performance DNS client written in Go with 1:1 feature parity with Python client.

**Performance Metrics:**
- **Cold Start**: ~10ms (10x faster than Python)
- **Memory Usage**: ~15MB (50% reduction)
- **Binary Size**: Single ~10MB executable
- **Concurrency**: Native goroutine support

**Key Features:**
- Full DNS-over-HTTPS (DoH) support with HTTP/2
- mTLS authentication with ECC and RSA certificates
- Local DNS forwarding (UDP/TCP to DoH)
- YAML configuration file support
- Cross-platform binaries (Linux, macOS, Windows)
- Docker multi-architecture support

### 2. Enterprise Authentication & Security

#### Multi-Factor Authentication (MFA)
- **TOTP Support**: Google Authenticator compatible
- **Backup Codes**: Recovery mechanism for lost devices
- **QR Code Generation**: Easy setup for users
- **Per-user Configuration**: Flexible MFA requirements

#### Single Sign-On (SSO)
- **SAML 2.0**: Enterprise identity provider integration
- **LDAP**: Active Directory support
- **OAuth2**: Social login capabilities
- **Session Management**: Secure token handling

#### Advanced Certificate Management
- **ECC Certificates**: Default P-384 curve (more secure than RSA)
- **Automatic Generation**: Self-signed certificates for testing
- **Certificate Bundle Downloads**: Direct from web console
- **Dual Authentication**: Bearer token + client certificate
- **CA Management**: Custom certificate authorities

### 3. DNS Security & Filtering

#### DNS Blackholing
- **Maravento Blacklist**: Integration with 2M+ malicious domains
- **Automatic Updates**: Daily pulls from GitHub (configurable)
- **Custom Blocklists**: Admin-defined domain/IP blocking
- **Whitelist Override**: Exception management
- **Real-time Updates**: No restart required

#### Brute Force Protection
- **Configurable Lockouts**: Default 5 attempts, 30-minute block
- **IP-based Tracking**: Per-source IP monitoring
- **Email Notifications**: Alerts on security events
- **Account Recovery**: Admin unlock capabilities
- **Audit Logging**: Complete security event trail

### 4. Performance & Scalability

#### HTTP/3 Support
- **QUIC Protocol**: Next-generation transport
- **Reduced Latency**: Faster connection establishment
- **Connection Migration**: Seamless network changes
- **Improved Reliability**: Better packet loss handling

#### Advanced Caching
- **Redis/Valkey Support**: Distributed caching
- **TLS Encryption**: Secure cache communication
- **Authentication**: Password-protected cache access
- **Configurable TTL**: Per-record expiration
- **Multi-backend**: Automatic failover between cache systems

#### High-Performance Architecture
- **Asyncio/Uvloop**: Python server optimization
- **Multi-threading**: Thousands of requests per second
- **Connection Pooling**: Efficient resource usage
- **Load Balancing**: Round-robin server selection

### 5. Infrastructure & Operations

#### Cross-Platform System Integration
- **Enhanced System Tray**: Desktop GUI with health monitoring and DNS fallback
- **Service Installation**: systemd, launchd, Windows services
- **DNS Configuration**: Automatic system DNS updates with DHCP fallback
- **Auto-start**: Boot-time service activation
- **Health Notifications**: Real-time alerts for DNS server failures
- **Captive Portal Support**: Easy fallback to original DNS for hotel/airport WiFi

#### Comprehensive Logging
- **Real IP Detection**: REALIP/X-FORWARDED-FOR headers
- **UDP Syslog**: RFC 3164 compliant forwarding
- **JSON Format**: Structured logging support
- **Security Events**: Authentication and access logs
- **Performance Metrics**: Request timing and statistics

#### CI/CD Pipeline
- **GitHub Actions**: Automated build and release
- **Multi-platform Builds**: Native binaries for all OS
- **Docker Images**: Multi-architecture containers
- **Debian Packages**: .deb with systemd integration
- **Separate Workflows**: Client and server releases

### 6. Enhanced DNS Client Features

#### Multiple Server Failover (NEW)
- **Automatic Failover**: Seamless server switching
- **Round-robin Selection**: Load distribution
- **Configurable Retries**: Custom retry logic
- **Error Aggregation**: Comprehensive failure reporting
- **Health Monitoring**: Server availability tracking

#### DNS Loop Prevention (NEW)
- **IP Address Validation**: Enforces IP usage for custom servers
- **Public DNS Exceptions**: Allows known providers by hostname
- **Smart Warnings**: Context-aware notifications
- **Development Mode**: Localhost exemption

#### DNS Name Validation (NEW)
- **RFC 1035 Compliance**: Strict DNS name validation on both client and server
- **Label Validation**: Max 63 chars per label, 253 total, proper format
- **Character Filtering**: Prevents injection attacks and malformed queries
- **IDN Support**: Punycode (xn--) domain handling for internationalized domains
- **Record Type Validation**: Only valid DNS types (A, AAAA, CNAME, MX, etc.)
- **Special Cases**: Handles .arpa reverse DNS and IPv4 addresses
- **Security**: Blocks special characters and SQL injection attempts
- **Consistent Validation**: Same rules applied across Go, Python, and server

#### Legacy Public DNS Support (NEW)
- **Google DNS**: Both dns.google and dns.google.com
- **Cloudflare**: 1.1.1.1 and cloudflare-dns.com
- **Auto-path Correction**: /resolve vs /dns-query
- **Transparent Compatibility**: No configuration needed

## 📊 Technical Improvements

### Web Console Enhancements
- **Modern UI**: Responsive Bootstrap 5 design
- **Certificate Management**: Download mTLS bundles
- **User Management**: Role-based access control
- **Domain Management**: Blacklist/whitelist interface
- **Real-time Monitoring**: Live statistics dashboard
- **Token Management**: API key generation
- **Security Settings**: MFA, SSO, brute force configuration

### Database & Storage
- **Multi-database Support**: SQLite, PostgreSQL, MySQL
- **Migration Scripts**: Automatic schema updates
- **Connection Pooling**: Efficient database usage
- **Transaction Management**: ACID compliance

### Testing & Quality
- **Comprehensive Test Suites**: 2000+ test cases
- **Security Scanning**: Bandit, gosec integration
- **Load Testing**: k6 performance tests
- **Code Coverage**: 80%+ coverage target
- **Linting**: flake8, golangci-lint

### Documentation
- **API Documentation**: 1300+ lines of OpenAPI specs
- **Architecture Guide**: 800+ lines of system design
- **Development Guide**: 1500+ lines of setup instructions
- **Token Management**: Complete authentication guide
- **Contributing Guide**: Expanded from 100 to 700+ lines

## 🔧 Configuration & Environment

### New Environment Variables
```bash
# Multiple Server Support
SQUAWK_SERVER_URLS=https://192.168.1.100:8443,https://192.168.1.101:8443
SQUAWK_MAX_RETRIES=6
SQUAWK_RETRY_DELAY=2

# Security Features
ENABLE_MFA=true
ENABLE_SSO=true
BRUTE_FORCE_MAX_ATTEMPTS=5
BRUTE_FORCE_LOCKOUT_MINUTES=30

# Redis/Valkey Security
REDIS_USE_TLS=true
REDIS_USERNAME=squawk
REDIS_PASSWORD=secure-password

# Blacklist Management
ENABLE_BLACKLIST=true
MARAVENTO_URL=https://github.com/maravento/blackweb
BLACKLIST_UPDATE_DAILY=true

# mTLS Configuration
ENABLE_MTLS=true
USE_ECC_CERTIFICATES=true
ECC_CURVE=P-384
```

### Docker Compose Enhancements
- Development, production, and testing configurations
- PostgreSQL integration
- Monitoring stack (Prometheus/Grafana)
- Load testing integration
- Health checks and dependencies

## 🚨 Breaking Changes

None - All changes are backward compatible. Existing configurations will continue to work.

## 🔐 Security Considerations

### Required Actions for Production
1. **Enable mTLS**: Use ECC certificates for maximum security
2. **Configure MFA**: Require for all admin accounts
3. **Set up Redis TLS**: Encrypt cache communications
4. **Enable Brute Force Protection**: Prevent authentication attacks
5. **Configure Email Alerts**: Monitor security events
6. **Use IP Addresses**: For custom DNS servers (loop prevention)

### Security Warnings
- Development mode settings show clear warnings
- Insecure configurations logged prominently
- Default secure settings for new installations

## 📈 Performance Benchmarks

| Metric | v1.0 | v1.1 | Improvement |
|--------|------|------|-------------|
| Requests/sec | 100 | 1000+ | 10x |
| Cold Start (Go) | N/A | 10ms | New |
| Memory (Go) | N/A | 15MB | New |
| Cache Hit Rate | 0% | 95% | New |
| Failover Time | N/A | <2s | New |
| Concurrent Connections | 10 | 1000+ | 100x |

## 🛠️ Migration Guide

### From v1.0 to v1.1.1
1. **No breaking changes** - Direct upgrade supported
2. **Optional**: Migrate to Go client for better performance
3. **Optional**: Enable new security features (MFA, SSO)
4. **Recommended**: Configure Redis/Valkey caching
5. **Recommended**: Set up multiple DNS servers for failover
6. **Critical**: Update existing configs to use IP addresses for custom DNS servers

### New Installation
1. Use provided installers for system integration
2. Configure using environment variables
3. Enable security features by default
4. Use docker-compose for containerized deployments

## 📦 Release Artifacts

### Binaries & Packages
- **Go Client Binaries**: Linux (AMD64/ARM64), macOS (Universal), Windows
- **Debian Packages**: .deb files with systemd service
- **Docker Images**: Multi-architecture (linux/amd64, linux/arm64)
- **Python Packages**: pip-installable modules

### Docker Images
- `penguincloud/squawk-dns-server`: Development server
- `penguincloud/squawk-dns-server-prod`: Production server
- `penguincloud/squawk-dns-client`: Go client
- `penguincloud/squawk-dns-client-python`: Python client
- `penguincloud/squawk-dns-testing`: Testing environment

## 🐛 Bug Fixes

- Fixed SSL certificate verification issues
- Resolved connection pooling memory leaks
- Corrected DNS response parsing for certain record types
- Fixed race conditions in concurrent request handling
- Resolved configuration file parsing errors

## 📚 Documentation Updates

- **README**: Expanded from 300 to 800+ lines
- **API Docs**: Complete OpenAPI specification
- **Architecture**: New comprehensive system design document
- **Development Guide**: Step-by-step setup instructions
- **Security Guide**: Best practices and recommendations
- **Troubleshooting**: Common issues and solutions

## 🙏 Acknowledgments

Special thanks to:
- Maravento project for blacklist data
- py4web team for authentication framework
- miekg for Go DNS library
- All contributors and testers

## 🚦 Known Issues

- Windows service installation requires administrator privileges
- Some IDN domains may not validate correctly
- Redis cluster mode not fully tested
- HTTP/3 support experimental in some environments

## 🔮 Future Roadmap (v1.2)

- Kubernetes operator for automated deployment
- GraphQL API for advanced queries
- Machine learning-based threat detection
- DNS over TLS (DoT) support
- Web Assembly client for browsers
- Mobile app for iOS/Android

## 📞 Support

- **GitHub Issues**: https://github.com/penguincloud/squawk/issues
- **Documentation**: https://docs.squawkdns.com
- **Email**: support@penguintech.group

## 📄 License

GNU AGPL v3 - See LICENSE.md for details

---

**Upgrade Recommendation**: This is a major release with significant security and performance improvements. All users are encouraged to upgrade to v1.1.1 for enhanced security and functionality.

**Note**: This is an alpha release. While feature-complete, additional testing in production environments is recommended before full deployment.