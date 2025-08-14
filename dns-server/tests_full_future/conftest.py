"""
Test configuration and fixtures for DNS server tests
Enhanced for new feature testing
"""
import pytest
import asyncio
import tempfile
import os
import sys
from unittest.mock import Mock, patch, AsyncMock
from pydal import DAL, Field
from datetime import datetime, timedelta

# Add web/apps directory to Python path for importing dns_console
web_apps_path = os.path.join(os.path.dirname(__file__), '..', 'web', 'apps')
if web_apps_path not in sys.path:
    sys.path.insert(0, web_apps_path)

# Add bins directory to Python path for importing feature modules
bins_path = os.path.join(os.path.dirname(__file__), '..', 'bins')
if bins_path not in sys.path:
    sys.path.insert(0, bins_path)

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def temp_db():
    """Create temporary SQLite database for testing"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    
    db = DAL(f'sqlite://{db_path}')
    
    # Define test tables
    db.define_table('tokens',
        Field('token', 'string', unique=True, notnull=True),
        Field('name', 'string', notnull=True),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=datetime.now),
        Field('last_used', 'datetime'),
        Field('active', 'boolean', default=True)
    )
    
    db.define_table('domains',
        Field('name', 'string', unique=True, notnull=True),
        Field('description', 'text'),
        Field('created_at', 'datetime', default=datetime.now)
    )
    
    db.define_table('token_domains',
        Field('token_id', 'reference tokens', notnull=True, ondelete='CASCADE'),
        Field('domain_id', 'reference domains', notnull=True, ondelete='CASCADE'),
        Field('created_at', 'datetime', default=datetime.now)
    )
    
    db.define_table('query_logs',
        Field('token_id', 'reference tokens', ondelete='SET NULL'),
        Field('domain_queried', 'string'),
        Field('query_type', 'string'),
        Field('status', 'string'),
        Field('client_ip', 'string'),
        Field('timestamp', 'datetime', default=datetime.now)
    )
    
    yield db
    
    # Cleanup
    db.close()
    os.unlink(db_path)

@pytest.fixture
def sample_token_data(temp_db):
    """Create sample token data for testing"""
    # Insert test token
    token_id = temp_db.tokens.insert(
        token='test-token-123456789',
        name='Test Token',
        description='Token for testing',
        active=True
    )
    
    # Insert test domain
    domain_id = temp_db.domains.insert(
        name='example.com',
        description='Test domain'
    )
    
    # Insert wildcard domain
    wildcard_id = temp_db.domains.insert(
        name='*',
        description='Wildcard domain'
    )
    
    # Grant permissions
    temp_db.token_domains.insert(token_id=token_id, domain_id=domain_id)
    
    temp_db.commit()
    
    return {
        'token_id': token_id,
        'domain_id': domain_id,
        'wildcard_id': wildcard_id,
        'token': 'test-token-123456789',
        'domain': 'example.com'
    }

@pytest.fixture
def mock_dns_handler():
    """Mock DNS handler for testing"""
    handler = Mock()
    handler.headers = {'Authorization': 'Bearer test-token-123456789'}
    handler.path = '/dns-query?name=example.com&type=A'
    handler.client_address = ('127.0.0.1', 12345)
    
    # Mock methods
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    handler.wfile = Mock()
    handler.wfile.write = Mock()
    
    return handler

@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver for testing"""
    with patch('dns.resolver.Resolver') as mock_resolver:
        mock_answer = Mock()
        mock_answer.to_text.return_value = '93.184.216.34'
        
        mock_resolver_instance = Mock()
        mock_resolver_instance.resolve.return_value = [mock_answer]
        mock_resolver.return_value = mock_resolver_instance
        
        yield mock_resolver_instance

@pytest.fixture
def sample_dns_response():
    """Sample DNS response data"""
    return {
        "Status": 0,
        "Answer": [
            {
                "name": "example.com",
                "type": "A",
                "data": "93.184.216.34"
            }
        ]
    }

@pytest.fixture
def invalid_domains():
    """List of invalid domain names for testing"""
    return [
        "",  # Empty domain
        "invalid..domain",  # Double dots
        "domain-",  # Trailing hyphen
        "-domain",  # Leading hyphen
        "very-long-domain-name-that-exceeds-the-maximum-length-limit-of-sixty-three-characters.com",
        "domain with spaces",  # Spaces
        "domain@invalid",  # Invalid characters
        "domain\x00.com",  # Null character
        "javascript:alert(1)",  # XSS attempt
    ]

@pytest.fixture
def valid_domains():
    """List of valid domain names for testing"""
    return [
        "example.com",
        "subdomain.example.com",
        "test-domain.co.uk",
        "a.b.c.example.org",
        "123.example.com",
        "localhost",
        "*.example.com",  # Wildcard
    ]

# Additional fixtures for new features
@pytest.fixture
def mock_whois_response():
    """Mock WHOIS response data"""
    return {
        'domain_name': 'example.com',
        'registrar': 'Example Registrar Inc.',
        'creation_date': '2000-01-01T00:00:00',
        'expiration_date': '2025-01-01T00:00:00',
        'nameservers': ['ns1.example.com', 'ns2.example.com'],
        'organization': 'Example Organization',
        'status': ['clientTransferProhibited'],
        'emails': ['admin@example.com'],
        'query_type': 'domain',
        'timestamp': datetime.now().isoformat(),
        'source': 'test'
    }

@pytest.fixture
def mock_ioc_feeds():
    """Mock IOC feed data"""
    return [
        {
            'name': 'Test Malware Domains',
            'url': 'https://test.example.com/malware_domains.txt',
            'feed_type': 'domain',
            'format': 'txt',
            'enabled': True,
            'content': 'malware.example.com\nphishing.test.com\nbad-domain.org\n'
        }
    ]

@pytest.fixture
def mock_client_config():
    """Mock client configuration data"""
    return {
        'server_url': 'https://dns.example.com:8443',
        'dns_port': 53,
        'cache_enabled': True,
        'cache_ttl': 300,
        'auth_token': 'test_token_123',
        'use_mtls': True,
        'cert_path': '/etc/squawk/client.crt',
        'key_path': '/etc/squawk/client.key',
        'ca_cert_path': '/etc/squawk/ca.crt',
        'log_level': 'INFO',
        'timeout': 5,
        'retries': 3
    }

@pytest.fixture
def test_jwt_secret():
    """Test JWT secret"""
    return "test_jwt_secret_key_for_unit_tests_only"