# Squawk Architecture Documentation

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Data Flow](#data-flow)
4. [Database Design](#database-design)
5. [Authentication & Authorization](#authentication--authorization)
6. [Security Architecture](#security-architecture)
7. [Performance Considerations](#performance-considerations)
8. [Scalability & Deployment](#scalability--deployment)
9. [Integration Points](#integration-points)
10. [Future Architecture Considerations](#future-architecture-considerations)

## System Overview

Squawk is a DNS-over-HTTPS (DoH) proxy system designed with a microservices architecture that provides secure, authenticated DNS resolution services. The system follows a modular design pattern with clear separation of concerns between DNS resolution, authentication, and management functions.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Squawk DNS System                         │
├─────────────────┬─────────────────┬─────────────────────────┤
│   DNS Client    │   DNS Server    │    Web Console          │
│                 │                 │                         │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────────┐ │
│ │UDP/TCP Port │ │ │HTTP(S) DoH  │ │ │Py4web Application   │ │
│ │53 Forwarder │ │ │Server       │ │ │                     │ │
│ └─────────────┘ │ │Port 8080/443│ │ │┌─────────────────┐  │ │
│                 │ └─────────────┘ │ ││Token Management │  │ │
│ ┌─────────────┐ │                 │ │└─────────────────┘  │ │
│ │DoH Client   │ │ ┌─────────────┐ │ │┌─────────────────┐  │ │
│ │Library      │ │ │Token Auth   │ │ ││Domain Control   │  │ │
│ └─────────────┘ │ │System       │ │ │└─────────────────┘  │ │
│                 │ └─────────────┘ │ │┌─────────────────┐  │ │
│ ┌─────────────┐ │                 │ ││Activity Logs    │  │ │
│ │Config Mgmt  │ │ ┌─────────────┐ │ │└─────────────────┘  │ │
│ └─────────────┘ │ │DNS Resolver │ │ │Port 8000            │ │
│                 │ │             │ │ └─────────────────────┘ │
│                 │ └─────────────┘ │                         │
└─────────────────┴─────────────────┴─────────────────────────┘
                         │
                ┌────────┴────────┐
                │   Database      │
                │   (SQLite/      │
                │   PostgreSQL/   │
                │   MySQL)        │
                └─────────────────┘
```

### Core Design Principles

1. **Security First**: All communications authenticated and encrypted
2. **Modular Design**: Clear separation between components
3. **Scalability**: Horizontal scaling capabilities
4. **Flexibility**: Support for multiple deployment scenarios
5. **Observability**: Comprehensive logging and monitoring
6. **Standards Compliance**: RFC 8484 DoH compliance

## Component Architecture

### DNS Server Component

The DNS server is the core component responsible for handling DNS-over-HTTPS requests.

```python
# Architecture Layer Breakdown
┌─────────────────────────────────────────┐
│            HTTP Handler Layer            │  ← Request routing, SSL termination
├─────────────────────────────────────────┤
│         Authentication Layer            │  ← Token validation, permission checks
├─────────────────────────────────────────┤
│            DNS Processing Layer         │  ← Query parsing, validation
├─────────────────────────────────────────┤
│           DNS Resolution Layer          │  ← Upstream DNS queries
├─────────────────────────────────────────┤
│             Database Layer              │  ← Token/domain storage
├─────────────────────────────────────────┤
│              Logging Layer              │  ← Activity logging, audit trails
└─────────────────────────────────────────┘
```

#### Key Components

**DNSHandler Class**
```python
class DNSHandler(http.server.BaseHTTPRequestHandler):
    """
    Main request handler implementing DoH protocol.
    
    Responsibilities:
    - HTTP request parsing
    - Authentication enforcement
    - DNS query processing
    - Response formatting
    - Error handling
    """
```

**Authentication System**
```python
def check_token_permission_new(token_value: str, domain_name: str) -> bool:
    """
    Multi-layered permission checking:
    1. Token existence and validity
    2. Token active status
    3. Domain permission resolution
    4. Wildcard and parent domain matching
    """
```

**DNS Resolution Engine**
```python
def resolve_dns(query: str, record_type: str = 'A') -> Dict[str, Any]:
    """
    DNS resolution with:
    - Multiple record type support
    - Error handling and retry logic
    - Response caching (future)
    - Upstream server failover
    """
```

### DNS Client Component

The client provides local DNS forwarding and DoH client functionality.

```
┌─────────────────────────────────────────┐
│          Configuration Layer            │  ← YAML config, CLI args
├─────────────────────────────────────────┤
│             DoH Client Layer            │  ← HTTPS DNS queries
├─────────────────────────────────────────┤
│        Local DNS Forwarder Layer       │  ← UDP/TCP port 53 handling
├─────────────────────────────────────────┤
│            Threading Layer              │  ← Concurrent request handling
├─────────────────────────────────────────┤
│             Caching Layer               │  ← Response caching (future)
└─────────────────────────────────────────┘
```

**Key Classes:**

```python
class DNSOverHTTPSClient:
    """
    Core DoH client implementation
    - HTTPS request handling
    - Authentication header management
    - Response parsing
    - Error handling and retries
    """

class DNSForwarder:
    """
    Local DNS forwarding service
    - UDP/TCP server on port 53
    - Threading for concurrent requests
    - Integration with DoH client
    - Legacy DNS compatibility
    """
```

### Web Console Component

Built on Py4web framework providing web-based management interface.

```
┌─────────────────────────────────────────┐
│              Web UI Layer               │  ← HTML templates, CSS, JS
├─────────────────────────────────────────┤
│            Controller Layer             │  ← Py4web actions/routes
├─────────────────────────────────────────┤
│              Business Logic             │  ← Token/domain management
├─────────────────────────────────────────┤
│              Database Layer             │  ← PyDAL ORM operations
├─────────────────────────────────────────┤
│               API Layer                 │  ← RESTful API endpoints
└─────────────────────────────────────────┘
```

**Application Structure:**
```
dns_console/
├── __init__.py              # Main application logic
├── templates/              # HTML templates
│   ├── layout.html         # Base template
│   ├── index.html          # Dashboard
│   ├── tokens.html         # Token management
│   ├── domains.html        # Domain management
│   ├── permissions.html    # Permission matrix
│   └── logs.html          # Activity logs
├── static/                # CSS, JS, images
└── databases/             # SQLite database files
```

## Data Flow

### DNS Query Flow

```
1. Client Request
   ├─ UDP/TCP DNS query to port 53 (if using local forwarder)
   │  └─ DNSForwarder → DNSOverHTTPSClient
   └─ Direct HTTPS DoH request

2. Server Processing  
   ├─ HTTP request parsing
   ├─ Authorization header extraction
   ├─ Token validation against database
   ├─ Domain permission checking
   ├─ DNS query parameter parsing
   ├─ Upstream DNS resolution
   ├─ Response formatting (JSON)
   └─ Activity logging

3. Response Flow
   ├─ JSON response to client
   ├─ Client parses JSON
   ├─ Convert to DNS format (if local forwarding)
   └─ Return to original requester
```

### Authentication Flow

```
1. Token Creation
   Web Console → Database → Token Generation → Permission Assignment

2. Token Validation
   DNS Request → Extract Token → Database Lookup → Permission Check → Allow/Deny

3. Permission Resolution
   Domain Request → Token Lookup → Domain Permissions → Wildcard Check → Parent Domain Check
```

### Data Synchronization

```
Web Console Database ←→ DNS Server Database
           │
           ├─ Real-time token validation
           ├─ Shared database schema
           ├─ Transaction consistency  
           └─ Activity logging coordination
```

## Database Design

### Entity Relationship Diagram

```
┌─────────────┐       ┌──────────────┐       ┌─────────────┐
│   tokens    │       │token_domains │       │   domains   │
├─────────────┤       ├──────────────┤       ├─────────────┤
│ id (PK)     │◄──────┤ token_id (FK)│       │ id (PK)     │
│ token       │       │ domain_id(FK)├──────►│ name        │
│ name        │       │ created_at   │       │ description │
│ description │       └──────────────┘       │ created_at  │
│ active      │                              └─────────────┘
│ created_at  │       
│ last_used   │       ┌──────────────┐
└─────────────┘       │ query_logs   │
                      ├──────────────┤
                      │ id (PK)      │
                      │ token_id(FK) │
                      │ domain_queried│
                      │ query_type   │
                      │ status       │
                      │ client_ip    │
                      │ timestamp    │
                      └──────────────┘
```

### Schema Design Rationale

**Tokens Table**: Central authentication entity
```sql
CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token VARCHAR(255) UNIQUE NOT NULL,          -- Unique auth token
    name VARCHAR(100) NOT NULL,                  -- Human-readable name
    description TEXT,                            -- Purpose documentation
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used DATETIME,                          -- Track usage
    active BOOLEAN DEFAULT TRUE                  -- Enable/disable tokens
);
```

**Domains Table**: Managed domain entities
```sql
CREATE TABLE domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) UNIQUE NOT NULL,           -- Domain name or wildcard
    description TEXT,                            -- Domain purpose
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Token_Domains Table**: Many-to-many relationship
```sql
CREATE TABLE token_domains (
    token_id INTEGER REFERENCES tokens(id) ON DELETE CASCADE,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (token_id, domain_id)           -- Composite key
);
```

**Query_Logs Table**: Audit and monitoring
```sql
CREATE TABLE query_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id INTEGER REFERENCES tokens(id) ON DELETE SET NULL,
    domain_queried VARCHAR(255) NOT NULL,       -- Domain that was queried
    query_type VARCHAR(10),                     -- A, AAAA, MX, etc.
    status VARCHAR(20),                         -- allowed, denied, error
    client_ip VARCHAR(45),                      -- IPv4/IPv6 client address
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Indexing Strategy

```sql
-- Performance indexes
CREATE INDEX idx_tokens_active ON tokens(active, token);
CREATE INDEX idx_tokens_token ON tokens(token);           -- Auth lookups
CREATE INDEX idx_token_domains_token ON token_domains(token_id);
CREATE INDEX idx_token_domains_domain ON token_domains(domain_id);
CREATE INDEX idx_domains_name ON domains(name);          -- Domain lookups
CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp DESC);
CREATE INDEX idx_query_logs_token ON query_logs(token_id);
CREATE INDEX idx_query_logs_status ON query_logs(status);
```

## Authentication & Authorization

### Token-Based Authentication

**Token Generation**
```python
def generate_token() -> str:
    """Generate cryptographically secure tokens using secrets module."""
    return secrets.token_urlsafe(32)  # 256-bit entropy
```

**Token Validation Process**
```python
def validate_token(token: str, domain: str) -> bool:
    """
    Multi-step validation:
    1. Token format validation
    2. Database lookup
    3. Active status check
    4. Domain permission verification
    5. Usage logging
    """
```

### Permission Model

**Permission Resolution Algorithm**
1. **Direct Match**: Token has explicit permission for domain
2. **Parent Domain**: Token has permission for parent domain
3. **Wildcard**: Token has wildcard (*) permission
4. **Subdomain Inheritance**: Permission cascades to subdomains

```python
def check_domain_permission(token_id: int, domain: str) -> bool:
    # 1. Check for wildcard permission
    if has_wildcard_permission(token_id):
        return True
    
    # 2. Check direct domain match
    if has_direct_permission(token_id, domain):
        return True
    
    # 3. Check parent domain permissions
    parts = domain.split('.')
    for i in range(len(parts)):
        parent_domain = '.'.join(parts[i:])
        if has_direct_permission(token_id, parent_domain):
            return True
    
    return False
```

### Security Model

**Defense in Depth**
1. **Transport Security**: HTTPS/TLS encryption
2. **Authentication**: Bearer token validation
3. **Authorization**: Domain-level permissions
4. **Input Validation**: Domain name sanitization
5. **Rate Limiting**: Request throttling (future)
6. **Audit Logging**: Complete activity trails

## Security Architecture

### Threat Model

**Threat Vectors Addressed:**
1. **Unauthorized DNS queries**: Token authentication
2. **Token compromise**: Domain-level restrictions
3. **DNS injection attacks**: Input validation
4. **Data exfiltration**: Permission boundaries
5. **Man-in-the-middle**: TLS encryption
6. **Replay attacks**: Token validation freshness

### Security Controls

**Input Validation**
```python
def is_valid_domain(domain: str) -> bool:
    """
    Comprehensive domain validation:
    - RFC-compliant format checking
    - Character whitelist enforcement
    - Length limits
    - Special character filtering
    """
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,6}\.?$'
    )
    return bool(pattern.match(domain))
```

**SQL Injection Prevention**
```python
# Using PyDAL ORM with parameterized queries
db((db.tokens.token == token_value) & (db.tokens.active == True)).select()
# Automatically parameterized - no string concatenation
```

**Token Security**
```python
def secure_token_comparison(provided: str, stored: str) -> bool:
    """Timing-attack resistant comparison."""
    return secrets.compare_digest(provided, stored)
```

### Audit and Compliance

**Activity Logging**
- All authentication attempts (success/failure)
- DNS query details with client IP
- Administrative actions via web console
- Token creation/modification/deletion
- Permission changes

**Log Format**
```json
{
    "timestamp": "2024-01-01T12:00:00Z",
    "event_type": "dns_query",
    "token_id": 123,
    "domain": "example.com",
    "query_type": "A", 
    "status": "allowed",
    "client_ip": "192.168.1.100",
    "response_time_ms": 150
}
```

## Performance Considerations

### Bottleneck Analysis

**Primary Performance Factors:**
1. **Database lookups**: Token validation on every request
2. **DNS resolution**: Upstream query latency
3. **Concurrent connections**: Thread/process limits
4. **Memory usage**: Token cache and DNS response cache

### Optimization Strategies

**Database Performance**
```sql
-- Optimized token lookup query
SELECT t.active, t.last_used 
FROM tokens t 
WHERE t.token = ? AND t.active = TRUE
LIMIT 1;

-- Domain permission check with index usage
SELECT 1 FROM token_domains td 
JOIN domains d ON td.domain_id = d.id 
WHERE td.token_id = ? AND d.name IN (?, ?, ?)
LIMIT 1;
```

**Connection Pooling**
```python
db = DAL(
    'postgresql://user:pass@host/db',
    pool_size=20,           # Connection pool
    pool_recycle=3600,      # Recycle connections hourly
    pool_pre_ping=True      # Validate connections
)
```

**Caching Strategy (Future)**
```python
class TokenCache:
    """In-memory token validation cache"""
    def __init__(self, ttl=300):  # 5-minute TTL
        self.cache = {}
        self.ttl = ttl
    
    def get_permissions(self, token: str) -> Optional[List[str]]:
        """Get cached token permissions"""
        pass
```

### Monitoring Metrics

**Key Performance Indicators:**
- Requests per second
- Average response time
- Database query time
- Cache hit ratio
- Error rate by type
- Token validation time

## Scalability & Deployment

### Horizontal Scaling

**Stateless Architecture**
- DNS server processes are stateless
- Shared database for token validation
- Load balancing friendly
- Session-less operation

**Scaling Patterns**
```yaml
# Load-balanced deployment
services:
  dns-server-1:
    image: squawk:latest
    environment:
      - NODE_ID=1
      - DATABASE_URL=postgresql://shared-db
  
  dns-server-2:
    image: squawk:latest 
    environment:
      - NODE_ID=2
      - DATABASE_URL=postgresql://shared-db
      
  load-balancer:
    image: nginx:latest
    ports:
      - "443:443"
    depends_on: [dns-server-1, dns-server-2]
```

### Database Scaling

**Read Replicas**
```python
# Separate read/write connections
write_db = DAL('postgresql://primary-db/squawk')
read_db = DAL('postgresql://replica-db/squawk')

def validate_token(token):
    # Use read replica for validation
    return read_db((read_db.tokens.token == token)).select()

def create_token(name, token):
    # Use primary for writes
    return write_db.tokens.insert(name=name, token=token)
```

**Sharding Strategy (Future)**
```python
def get_shard_for_token(token: str) -> str:
    """Route tokens to shards based on hash"""
    shard_id = hash(token) % SHARD_COUNT
    return f"shard_{shard_id}"
```

### Deployment Architectures

**Single Node (Development)**
```
┌─────────────────────────────────┐
│         Single Host             │
│  ┌─────────┐ ┌──────────────┐   │
│  │DNS Server│ │Web Console   │   │
│  │Port 8080 │ │Port 8000     │   │
│  └─────────┘ └──────────────┘   │
│  ┌─────────────────────────────┐ │
│  │       SQLite Database       │ │
│  └─────────────────────────────┘ │
└─────────────────────────────────┘
```

**High Availability (Production)**
```
┌─────────────────────────────────────────────────────────┐
│                Load Balancer                            │
└─────────────────────┬───────────────────────────────────┘
                      │
      ┌───────────────┼───────────────┐
      │               │               │
┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
│DNS Server │   │DNS Server │   │DNS Server │
│   Node 1  │   │   Node 2  │   │   Node 3  │
└───────────┘   └───────────┘   └───────────┘
      │               │               │
      └───────────────┼───────────────┘
                      │
      ┌───────────────▼───────────────┐
      │        Database Cluster       │
      │  ┌─────────┐ ┌──────────────┐ │
      │  │Primary  │ │Read Replicas │ │
      │  └─────────┘ └──────────────┘ │
      └───────────────────────────────┘
```

**Containerized (Kubernetes)**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: squawk-dns
spec:
  replicas: 3
  selector:
    matchLabels:
      app: squawk-dns
  template:
    spec:
      containers:
      - name: dns-server
        image: squawk:latest
        resources:
          limits:
            memory: "256Mi"
            cpu: "200m"
          requests:
            memory: "128Mi" 
            cpu: "100m"
```

## Integration Points

### External System Integration

**Upstream DNS Providers**
```python
UPSTREAM_RESOLVERS = [
    '8.8.8.8',      # Google DNS
    '8.8.4.4',      # Google DNS Secondary  
    '1.1.1.1',      # Cloudflare
    '1.0.0.1',      # Cloudflare Secondary
    '208.67.222.222', # OpenDNS
]
```

**Monitoring Integration**
```python
# Prometheus metrics
from prometheus_client import Counter, Histogram

dns_queries_total = Counter('dns_queries_total', 'Total DNS queries')
dns_query_duration = Histogram('dns_query_duration_seconds', 'DNS query duration')
auth_failures_total = Counter('auth_failures_total', 'Authentication failures')
```

**SIEM Integration**
```python
def emit_security_event(event_type: str, details: dict):
    """Send security events to SIEM system"""
    syslog.syslog(syslog.LOG_AUTH | syslog.LOG_WARNING,
                  f"SQUAWK_SECURITY: {event_type} - {json.dumps(details)}")
```

### API Integration

**RESTful API Design**
```python
# Token management API
GET    /api/v1/tokens              # List tokens
POST   /api/v1/tokens              # Create token
GET    /api/v1/tokens/{id}         # Get token details
PUT    /api/v1/tokens/{id}         # Update token
DELETE /api/v1/tokens/{id}         # Delete token

# Domain management API  
GET    /api/v1/domains             # List domains
POST   /api/v1/domains             # Add domain
DELETE /api/v1/domains/{id}        # Remove domain

# Permission management API
GET    /api/v1/permissions         # List all permissions
POST   /api/v1/permissions         # Grant permission
DELETE /api/v1/permissions         # Revoke permission
```

### Service Discovery

**Consul Integration**
```python
import consul

def register_service():
    """Register DNS service with Consul"""
    c = consul.Consul()
    c.agent.service.register(
        name='squawk-dns',
        service_id=f'squawk-dns-{NODE_ID}',
        port=8080,
        check=consul.Check.http('http://localhost:8080/health', 
                               interval='10s')
    )
```

## Future Architecture Considerations

### Planned Enhancements

**Response Caching**
```python
class DNSResponseCache:
    """Distributed DNS response caching"""
    def __init__(self):
        self.redis = redis.Redis(host='cache-cluster')
    
    def get_cached_response(self, query: str, record_type: str):
        key = f"dns:{query}:{record_type}"
        return self.redis.get(key)
```

**Rate Limiting**
```python
class TokenRateLimit:
    """Token-based rate limiting"""
    def check_rate_limit(self, token: str) -> bool:
        # Sliding window rate limiting
        pass
```

**Geographic Distribution**
```
┌─────────────────────────────────────────────────┐
│                 Global DNS                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐│
│  │   US East   │ │   Europe    │ │  Asia Pac   ││
│  │             │ │             │ │             ││
│  │┌───────────┐│ │┌───────────┐│ │┌───────────┐││
│  ││DNS Cluster││ ││DNS Cluster││ ││DNS Cluster│││
│  │└───────────┘│ │└───────────┘│ │└───────────┘││
│  └─────────────┘ └─────────────┘ └─────────────┘│
│                       │                         │
│  ┌─────────────────────┴─────────────────────┐   │
│  │         Global Token Database            │   │
│  │        (Master-Master Replication)       │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

### Technology Evolution

**Emerging Standards**
- DNS-over-TLS (DoT) support
- DNS-over-QUIC (DoQ) integration
- DNSSEC validation
- DNS64/NAT64 support

**Cloud-Native Features**
- Service mesh integration
- Istio/Envoy proxy support
- Kubernetes operator
- Helm chart improvements

**Performance Enhancements**
- Connection pooling improvements
- Async/await request handling
- gRPC internal communication
- Protocol buffer serialization

This architecture document provides a comprehensive overview of Squawk's design principles, component interactions, and future evolution path. The system is designed to be secure, scalable, and maintainable while providing excellent performance for DNS resolution services.