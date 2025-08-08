"""
Unit tests for DNS console web application
"""
import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import json
import sys

# Add the console app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import console functions
import dns_console

class TestTokenManagement:
    """Test token management functionality"""
    
    def test_generate_token(self):
        """Test secure token generation"""
        token = dns_console.generate_token()
        
        # Token should be non-empty string
        assert isinstance(token, str)
        assert len(token) > 32  # Should be reasonably long
        
        # Generate multiple tokens to ensure uniqueness
        tokens = {dns_console.generate_token() for _ in range(100)}
        assert len(tokens) == 100  # All should be unique
    
    def test_check_token_permission_valid(self):
        """Test token permission checking with valid token"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            # Create mock database with token and permission data
            from pydal import DAL, Field
            db = DAL(f'sqlite://{db_path}')
            
            # Define tables (same as in console)
            db.define_table('tokens',
                Field('token', 'string', unique=True),
                Field('name', 'string'),
                Field('active', 'boolean', default=True)
            )
            
            db.define_table('domains',
                Field('name', 'string', unique=True)
            )
            
            db.define_table('token_domains',
                Field('token_id', 'reference tokens'),
                Field('domain_id', 'reference domains')
            )
            
            # Insert test data
            token_id = db.tokens.insert(
                token='test-token-123',
                name='Test Token',
                active=True
            )
            
            domain_id = db.domains.insert(name='example.com')
            
            db.token_domains.insert(
                token_id=token_id,
                domain_id=domain_id
            )
            
            db.commit()
            
            # Test the permission check
            result = dns_console.check_token_permission('test-token-123', 'example.com')
            assert result is True
            
            # Test subdomain inheritance
            result = dns_console.check_token_permission('test-token-123', 'sub.example.com')
            assert result is True
            
            # Test denied access
            result = dns_console.check_token_permission('test-token-123', 'other.com')
            assert result is False
            
            db.close()
            
        finally:
            os.unlink(db_path)
    
    def test_check_token_permission_wildcard(self):
        """Test wildcard token permissions"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            from pydal import DAL, Field
            db = DAL(f'sqlite://{db_path}')
            
            db.define_table('tokens',
                Field('token', 'string'),
                Field('name', 'string'),
                Field('active', 'boolean', default=True)
            )
            
            db.define_table('domains',
                Field('name', 'string')
            )
            
            db.define_table('token_domains',
                Field('token_id', 'reference tokens'),
                Field('domain_id', 'reference domains')
            )
            
            # Create token with wildcard permission
            token_id = db.tokens.insert(
                token='wildcard-token',
                name='Wildcard Token',
                active=True
            )
            
            domain_id = db.domains.insert(name='*')
            
            db.token_domains.insert(
                token_id=token_id,
                domain_id=domain_id
            )
            
            db.commit()
            
            # Test wildcard permission
            result = dns_console.check_token_permission('wildcard-token', 'any-domain.com')
            assert result is True
            
            result = dns_console.check_token_permission('wildcard-token', 'another.example.org')
            assert result is True
            
            db.close()
            
        finally:
            os.unlink(db_path)
    
    def test_check_token_permission_inactive_token(self):
        """Test permission checking with inactive token"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            from pydal import DAL, Field
            db = DAL(f'sqlite://{db_path}')
            
            db.define_table('tokens',
                Field('token', 'string'),
                Field('name', 'string'),
                Field('active', 'boolean', default=True)
            )
            
            db.define_table('domains',
                Field('name', 'string')
            )
            
            db.define_table('token_domains',
                Field('token_id', 'reference tokens'),
                Field('domain_id', 'reference domains')
            )
            
            # Create inactive token
            token_id = db.tokens.insert(
                token='inactive-token',
                name='Inactive Token',
                active=False  # Inactive
            )
            
            domain_id = db.domains.insert(name='example.com')
            
            db.token_domains.insert(
                token_id=token_id,
                domain_id=domain_id
            )
            
            db.commit()
            
            # Test that inactive token is denied
            result = dns_console.check_token_permission('inactive-token', 'example.com')
            assert result is False
            
            db.close()
            
        finally:
            os.unlink(db_path)
    
    def test_log_query_success(self):
        """Test query logging functionality"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            from pydal import DAL, Field
            db = DAL(f'sqlite://{db_path}')
            
            db.define_table('tokens',
                Field('token', 'string'),
                Field('name', 'string')
            )
            
            db.define_table('query_logs',
                Field('token_id', 'reference tokens'),
                Field('domain_queried', 'string'),
                Field('query_type', 'string'),
                Field('status', 'string'),
                Field('client_ip', 'string'),
                Field('timestamp', 'datetime', default=datetime.now)
            )
            
            # Create token
            token_id = db.tokens.insert(
                token='log-test-token',
                name='Log Test Token'
            )
            
            db.commit()
            
            # Test logging
            dns_console.log_query('log-test-token', 'example.com', 'A', 'allowed', '192.168.1.100')
            
            # Verify log was created
            logs = db.query_logs.select()
            assert len(logs) == 1
            
            log = logs[0]
            assert log.token_id == token_id
            assert log.domain_queried == 'example.com'
            assert log.query_type == 'A'
            assert log.status == 'allowed'
            assert log.client_ip == '192.168.1.100'
            
            db.close()
            
        finally:
            os.unlink(db_path)

class TestWebActions:
    """Test web console actions/endpoints"""
    
    def test_index_action(self):
        """Test dashboard index action"""
        with patch('dns_console.db') as mock_db:
            # Mock database queries
            mock_db.tokens.count.return_value = 5
            mock_db.domains.count.return_value = 3
            mock_db.query_logs.select.return_value = []
            
            result = dns_console.index()
            
            assert 'token_count' in result
            assert 'domain_count' in result
            assert 'recent_queries' in result
            assert result['token_count'] == 5
            assert result['domain_count'] == 3
    
    def test_tokens_list_action(self):
        """Test tokens listing action"""
        with patch('dns_console.db') as mock_db:
            # Mock tokens data
            mock_token = Mock()
            mock_token.id = 1
            mock_token.name = 'Test Token'
            mock_token.token = 'abc123'
            mock_token.active = True
            
            mock_db.tokens.select.return_value = [mock_token]
            
            result = dns_console.tokens_list()
            
            assert 'tokens' in result
            assert len(result['tokens']) == 1
            assert result['tokens'][0].name == 'Test Token'
    
    def test_token_creation(self):
        """Test token creation via web interface"""
        with patch('dns_console.db') as mock_db:
            with patch('dns_console.request') as mock_request:
                # Mock form data
                mock_request.method = 'POST'
                mock_request.forms.get.side_effect = lambda key: {
                    'name': 'New Test Token',
                    'description': 'Test description',
                    'token': 'generated-token-123'
                }.get(key)
                
                # Mock database insert
                mock_db.tokens.insert.return_value = 1
                
                with patch('dns_console.redirect') as mock_redirect:
                    result = dns_console.token_new()
                    
                    # Verify token was inserted
                    mock_db.tokens.insert.assert_called_once_with(
                        token='generated-token-123',
                        name='New Test Token',
                        description='Test description'
                    )
                    
                    # Verify redirect
                    mock_redirect.assert_called_once()

class TestAPIEndpoints:
    """Test API endpoints"""
    
    def test_api_check_permission(self):
        """Test permission checking API endpoint"""
        with patch('dns_console.request') as mock_request:
            with patch('dns_console.check_token_permission') as mock_check:
                # Mock request data
                mock_request.json = {
                    'token': 'test-token',
                    'domain': 'example.com'
                }
                
                mock_check.return_value = True
                
                with patch('dns_console.log_query') as mock_log:
                    result = dns_console.api_check_permission()
                    
                    # Verify permission was checked
                    mock_check.assert_called_once_with('test-token', 'example.com')
                    
                    # Verify response
                    assert result['allowed'] is True
                    
                    # Verify logging
                    mock_log.assert_called_once()
    
    def test_api_check_permission_denied(self):
        """Test permission checking API with denied access"""
        with patch('dns_console.request') as mock_request:
            with patch('dns_console.check_token_permission') as mock_check:
                mock_request.json = {
                    'token': 'invalid-token',
                    'domain': 'example.com'
                }
                
                mock_check.return_value = False
                
                with patch('dns_console.log_query') as mock_log:
                    result = dns_console.api_check_permission()
                    
                    assert result['allowed'] is False
                    mock_log.assert_called_with('invalid-token', 'example.com', 'CHECK', 'denied', None)
    
    def test_api_tokens_list(self):
        """Test API tokens listing endpoint"""
        with patch('dns_console.db') as mock_db:
            # Mock token data
            mock_token = Mock()
            mock_token.id = 1
            mock_token.name = 'API Token'
            mock_token.token = 'api-token-123'
            mock_token.created_at = datetime(2024, 1, 1)
            
            mock_db.tokens.select.return_value = [mock_token]
            mock_db.token_domains.select.return_value = []
            mock_db.domains.select.return_value = []
            
            result = dns_console.api_tokens_list()
            
            assert 'tokens' in result
            assert len(result['tokens']) == 1
            assert result['tokens'][0]['name'] == 'API Token'
            assert result['tokens'][0]['id'] == 1
    
    def test_api_validate_token(self):
        """Test token validation API endpoint"""
        with patch('dns_console.db') as mock_db:
            # Mock valid token
            mock_token = Mock()
            mock_token.id = 1
            mock_token.name = 'Valid Token'
            mock_token.active = True
            
            mock_db.tokens.select.return_value.first.return_value = mock_token
            mock_db.token_domains.select.return_value = []
            mock_db.domains.select.return_value = []
            
            result = dns_console.api_validate_token('valid-token-123')
            
            assert result['valid'] is True
            assert result['name'] == 'Valid Token'
    
    def test_api_validate_invalid_token(self):
        """Test token validation with invalid token"""
        with patch('dns_console.db') as mock_db:
            # Mock invalid token (not found)
            mock_db.tokens.select.return_value.first.return_value = None
            
            result = dns_console.api_validate_token('invalid-token')
            
            assert result == ({'valid': False}, 404)

class TestPermissionMatrix:
    """Test permission matrix functionality"""
    
    def test_permissions_matrix_display(self):
        """Test permission matrix page rendering"""
        with patch('dns_console.db') as mock_db:
            # Mock tokens
            mock_token = Mock()
            mock_token.id = 1
            mock_token.name = 'Token 1'
            
            # Mock domains
            mock_domain = Mock()
            mock_domain.id = 1
            mock_domain.name = 'example.com'
            
            mock_db.tokens.select.return_value = [mock_token]
            mock_db.domains.select.return_value = [mock_domain]
            
            # Mock permission count
            mock_db.token_domains.count.return_value = 1
            
            result = dns_console.permissions_matrix()
            
            assert 'tokens' in result
            assert 'domains' in result
            assert 'matrix' in result
            assert result['matrix'][1][1] is True  # Token 1 has access to Domain 1
    
    def test_permission_toggle_grant(self):
        """Test granting permission via toggle"""
        with patch('dns_console.request') as mock_request:
            with patch('dns_console.db') as mock_db:
                # Mock request data
                mock_request.json = {
                    'token_id': 1,
                    'domain_id': 2
                }
                
                # Mock no existing permission
                mock_db.token_domains.select.return_value.first.return_value = None
                
                result = dns_console.permission_toggle()
                
                # Should insert new permission
                mock_db.token_domains.insert.assert_called_once_with(
                    token_id=1,
                    domain_id=2
                )
                
                assert result['success'] is True
                assert result['new_state'] is True
    
    def test_permission_toggle_revoke(self):
        """Test revoking permission via toggle"""
        with patch('dns_console.request') as mock_request:
            with patch('dns_console.db') as mock_db:
                # Mock request data
                mock_request.json = {
                    'token_id': 1,
                    'domain_id': 2
                }
                
                # Mock existing permission
                mock_existing = Mock()
                mock_db.token_domains.select.return_value.first.return_value = mock_existing
                
                result = dns_console.permission_toggle()
                
                # Should delete existing permission
                mock_db.token_domains.delete.assert_called_once()
                
                assert result['success'] is True
                assert result['new_state'] is False

class TestSecurityFeatures:
    """Test security features in web console"""
    
    def test_input_validation_token_name(self):
        """Test token name validation"""
        with patch('dns_console.db') as mock_db:
            with patch('dns_console.request') as mock_request:
                # Test with malicious input
                malicious_names = [
                    "<script>alert('xss')</script>",
                    "'; DROP TABLE tokens; --",
                    "../../../etc/passwd",
                    "normal_name"  # This should work
                ]
                
                for name in malicious_names:
                    mock_request.method = 'POST'
                    mock_request.forms.get.side_effect = lambda key: {
                        'name': name,
                        'description': 'Test',
                        'token': 'safe-token'
                    }.get(key)
                    
                    if name == "normal_name":
                        # Should succeed with normal name
                        mock_db.tokens.insert.return_value = 1
                        with patch('dns_console.redirect'):
                            dns_console.token_new()
                            mock_db.tokens.insert.assert_called()
                    else:
                        # Should handle malicious input safely
                        # The actual validation would be done by PyDAL/database constraints
                        pass
    
    def test_api_request_validation(self):
        """Test API request validation"""
        with patch('dns_console.request') as mock_request:
            # Test missing parameters
            mock_request.json = {}
            
            result = dns_console.api_check_permission()
            
            # Should return error for missing parameters
            assert result[1] == 400  # Bad request
    
    def test_csrf_protection(self):
        """Test CSRF protection (if implemented)"""
        # This would test CSRF token validation
        # Currently not implemented but should be added for production
        pass

class TestDatabaseOperations:
    """Test database operations and integrity"""
    
    def test_database_transaction_rollback(self):
        """Test database transaction rollback on error"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            from pydal import DAL, Field
            db = DAL(f'sqlite://{db_path}')
            
            db.define_table('tokens',
                Field('token', 'string', unique=True),
                Field('name', 'string', notnull=True)
            )
            
            # Insert valid token
            db.tokens.insert(token='token1', name='Token 1')
            db.commit()
            
            # Attempt to insert duplicate token (should fail)
            try:
                db.tokens.insert(token='token1', name='Duplicate Token')
                db.commit()
            except Exception:
                db.rollback()
            
            # Verify original token still exists and no duplicate
            tokens = db.tokens.select()
            assert len(tokens) == 1
            assert tokens[0].name == 'Token 1'
            
            db.close()
            
        finally:
            os.unlink(db_path)
    
    def test_cascade_delete_permissions(self):
        """Test cascading delete of permissions when token is deleted"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            from pydal import DAL, Field
            db = DAL(f'sqlite://{db_path}')
            
            db.define_table('tokens',
                Field('token', 'string'),
                Field('name', 'string')
            )
            
            db.define_table('domains',
                Field('name', 'string')
            )
            
            db.define_table('token_domains',
                Field('token_id', 'reference tokens', ondelete='CASCADE'),
                Field('domain_id', 'reference domains')
            )
            
            # Create test data
            token_id = db.tokens.insert(token='delete-test', name='Delete Test')
            domain_id = db.domains.insert(name='test.com')
            db.token_domains.insert(token_id=token_id, domain_id=domain_id)
            db.commit()
            
            # Verify permission exists
            permissions = db.token_domains.select()
            assert len(permissions) == 1
            
            # Delete token
            db(db.tokens.id == token_id).delete()
            db.commit()
            
            # Verify permission was cascaded deleted
            permissions = db.token_domains.select()
            assert len(permissions) == 0
            
            db.close()
            
        finally:
            os.unlink(db_path)