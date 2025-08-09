"""
Test configuration and fixtures for DNS server tests
"""
import pytest
import tempfile
import os
import sys
from unittest.mock import Mock, patch
from pydal import DAL, Field
from datetime import datetime

# Add web/apps directory to Python path for importing dns_console
web_apps_path = os.path.join(os.path.dirname(__file__), '..', 'web', 'apps')
if web_apps_path not in sys.path:
    sys.path.insert(0, web_apps_path)

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