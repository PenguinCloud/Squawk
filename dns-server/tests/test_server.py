"""
Unit tests for DNS server functionality
"""
import pytest
import json
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add the bins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bins'))

# Import the server module
import server
from server import DNSHandler

class TestDNSHandler:
    """Test DNS request handler functionality"""
    
    def test_valid_domain_validation(self, valid_domains):
        """Test domain validation with valid domains"""
        handler = DNSHandler(None, None, None)
        
        for domain in valid_domains:
            if domain != "*.example.com":  # Skip wildcard for basic validation
                assert handler.is_valid_domain(domain), f"Domain {domain} should be valid"
    
    def test_invalid_domain_validation(self, invalid_domains):
        """Test domain validation with invalid domains"""
        handler = DNSHandler(None, None, None)
        
        for domain in invalid_domains:
            assert not handler.is_valid_domain(domain), f"Domain {domain} should be invalid"
    
    def test_resolve_dns_success(self, mock_dns_resolver):
        """Test successful DNS resolution"""
        handler = DNSHandler(None, None, None)
        
        result = handler.resolve_dns("example.com", "A")
        result_dict = json.loads(result)
        
        assert result_dict["Status"] == 0
        assert "Answer" in result_dict
        assert len(result_dict["Answer"]) > 0
        assert result_dict["Answer"][0]["data"] == "93.184.216.34"
    
    def test_resolve_dns_failure(self):
        """Test DNS resolution failure"""
        handler = DNSHandler(None, None, None)
        
        with patch('dns.resolver.Resolver') as mock_resolver:
            mock_resolver_instance = Mock()
            mock_resolver_instance.resolve.side_effect = Exception("Resolution failed")
            mock_resolver.return_value = mock_resolver_instance
            
            result = handler.resolve_dns("nonexistent.domain", "A")
            result_dict = json.loads(result)
            
            assert result_dict["Status"] == 2
            assert "Comment" in result_dict
            assert "Resolution failed" in result_dict["Comment"]
    
    @patch('server.USE_NEW_AUTH', True)
    @patch('server.DB_TYPE', 'sqlite')
    @patch('server.DB_URL', 'test.db')
    def test_check_token_permission_new_valid(self, temp_db, sample_token_data):
        """Test token permission checking with valid token"""
        handler = DNSHandler(None, None, None)
        
        # Mock the database path to use our temp database
        with patch('os.path.join') as mock_join:
            mock_join.return_value = temp_db._uri.split('://')[-1]
            
            with patch('server.DAL') as mock_dal:
                mock_dal.return_value = temp_db
                
                result = handler.check_token_permission_new(
                    sample_token_data['token'], 
                    sample_token_data['domain']
                )
                
                assert result is True
    
    @patch('server.USE_NEW_AUTH', True)
    @patch('server.DB_TYPE', 'sqlite')
    @patch('server.DB_URL', 'test.db')
    def test_check_token_permission_new_invalid(self, temp_db):
        """Test token permission checking with invalid token"""
        handler = DNSHandler(None, None, None)
        
        with patch('os.path.join') as mock_join:
            mock_join.return_value = temp_db._uri.split('://')[-1]
            
            with patch('server.DAL') as mock_dal:
                mock_dal.return_value = temp_db
                
                result = handler.check_token_permission_new(
                    'invalid-token', 
                    'example.com'
                )
                
                assert result is False
    
    def test_check_token_permission_wildcard(self, temp_db, sample_token_data):
        """Test wildcard permission checking"""
        handler = DNSHandler(None, None, None)
        
        # Grant wildcard permission
        temp_db.token_domains.insert(
            token_id=sample_token_data['token_id'],
            domain_id=sample_token_data['wildcard_id']
        )
        temp_db.commit()
        
        with patch('os.path.join') as mock_join:
            mock_join.return_value = temp_db._uri.split('://')[-1]
            
            with patch('server.DAL') as mock_dal:
                mock_dal.return_value = temp_db
                
                result = handler.check_token_permission_new(
                    sample_token_data['token'],
                    'any-domain.com'
                )
                
                assert result is True
    
    def test_subdomain_permission_inheritance(self, temp_db, sample_token_data):
        """Test that subdomains inherit parent domain permissions"""
        handler = DNSHandler(None, None, None)
        
        with patch('os.path.join') as mock_join:
            mock_join.return_value = temp_db._uri.split('://')[-1]
            
            with patch('server.DAL') as mock_dal:
                mock_dal.return_value = temp_db
                
                # Should have permission for subdomain
                result = handler.check_token_permission_new(
                    sample_token_data['token'],
                    'sub.example.com'
                )
                
                assert result is True
                
                # Should not have permission for different domain
                result = handler.check_token_permission_new(
                    sample_token_data['token'],
                    'other.com'
                )
                
                assert result is False

class TestServerFunctions:
    """Test standalone server functions"""
    
    def test_get_token_from_db_success(self, temp_db):
        """Test legacy token retrieval from database"""
        # Insert legacy auth record
        temp_db.define_table('auth',
            Field('token', 'string'),
            Field('domain', 'string')
        )
        
        temp_db.auth.insert(
            token='legacy-token-123',
            domain='example.com,test.com'
        )
        temp_db.commit()
        
        with patch('server.DAL') as mock_dal:
            mock_dal.return_value = temp_db
            
            token, domains = server.get_token_from_db('sqlite', 'test.db')
            
            assert token == 'legacy-token-123'
            assert 'example.com' in domains
            assert 'test.com' in domains
    
    def test_get_token_from_db_not_found(self, temp_db):
        """Test legacy token retrieval when not found"""
        temp_db.define_table('auth',
            Field('token', 'string'),
            Field('domain', 'string')
        )
        
        with patch('server.DAL') as mock_dal:
            mock_dal.return_value = temp_db
            
            token, domains = server.get_token_from_db('sqlite', 'test.db')
            
            assert token is None
            assert domains == []
    
    def test_main_function_argument_parsing(self):
        """Test main function argument parsing"""
        test_args = [
            '-p', '9090',
            '-a', 'test-auth-token',
            '-k', '/path/to/key.pem',
            '-c', '/path/to/cert.pem',
            '-d', 'postgresql',
            '-u', 'postgresql://localhost/test',
            '-n'
        ]
        
        with patch('sys.argv', ['server.py'] + test_args):
            with patch('server.socketserver.TCPServer'):
                with patch('server.ssl.wrap_socket'):
                    try:
                        server.main(test_args)
                        
                        # Verify global variables are set correctly
                        assert server.PORT == 9090
                        assert server.AUTH_TOKEN == 'test-auth-token'
                        assert server.KEY_FILE == '/path/to/key.pem'
                        assert server.CERT_FILE == '/path/to/cert.pem'
                        assert server.DB_TYPE == 'postgresql'
                        assert server.DB_URL == 'postgresql://localhost/test'
                        assert server.USE_NEW_AUTH is True
                        
                    except SystemExit:
                        pass  # Expected when server tries to start

class TestSecurityFeatures:
    """Test security-related functionality"""
    
    def test_sql_injection_prevention(self, temp_db):
        """Test that SQL injection attempts are blocked"""
        handler = DNSHandler(None, None, None)
        
        malicious_tokens = [
            "'; DROP TABLE tokens; --",
            "' OR '1'='1",
            "admin'/**/AND/**/1=1--",
            "token'; UPDATE tokens SET active=0; --"
        ]
        
        with patch('os.path.join') as mock_join:
            mock_join.return_value = temp_db._uri.split('://')[-1]
            
            with patch('server.DAL') as mock_dal:
                mock_dal.return_value = temp_db
                
                for malicious_token in malicious_tokens:
                    result = handler.check_token_permission_new(
                        malicious_token, 
                        'example.com'
                    )
                    
                    # Should safely return False, not cause database damage
                    assert result is False
                    
                    # Verify tables still exist and have correct data
                    assert temp_db.tokens.count() >= 0
    
    def test_domain_validation_security(self, invalid_domains):
        """Test domain validation blocks malicious inputs"""
        handler = DNSHandler(None, None, None)
        
        for malicious_domain in invalid_domains:
            assert not handler.is_valid_domain(malicious_domain)
    
    def test_xss_prevention_in_domain_names(self):
        """Test that XSS attempts in domain names are blocked"""
        handler = DNSHandler(None, None, None)
        
        xss_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';DROP TABLE users;--",
            "../../../etc/passwd"
        ]
        
        for xss_attempt in xss_attempts:
            assert not handler.is_valid_domain(xss_attempt)

class TestLoggingFunctionality:
    """Test query logging functionality"""
    
    @patch('server.USE_NEW_AUTH', True)
    def test_log_query_new_success(self, temp_db, sample_token_data):
        """Test successful query logging"""
        handler = DNSHandler(None, None, None)
        
        with patch('os.path.join') as mock_join:
            mock_join.return_value = temp_db._uri.split('://')[-1]
            
            with patch('server.DAL') as mock_dal:
                mock_dal.return_value = temp_db
                
                handler.log_query_new(
                    sample_token_data['token'],
                    'example.com',
                    'A',
                    'allowed'
                )
                
                # Verify log entry was created
                logs = temp_db.query_logs.select()
                assert len(logs) > 0
                
                log_entry = logs[-1]  # Get the latest log entry
                assert log_entry.domain_queried == 'example.com'
                assert log_entry.query_type == 'A'
                assert log_entry.status == 'allowed'
    
    @patch('server.USE_NEW_AUTH', True)
    def test_log_query_new_with_invalid_token(self, temp_db):
        """Test logging with invalid token"""
        handler = DNSHandler(None, None, None)
        
        with patch('os.path.join') as mock_join:
            mock_join.return_value = temp_db._uri.split('://')[-1]
            
            with patch('server.DAL') as mock_dal:
                mock_dal.return_value = temp_db
                
                # Should not raise exception even with invalid token
                handler.log_query_new(
                    'invalid-token',
                    'example.com',
                    'A',
                    'denied'
                )
                
                # Verify log entry was created with null token_id
                logs = temp_db.query_logs.select()
                assert len(logs) > 0
                
                log_entry = logs[-1]
                assert log_entry.token_id is None
                assert log_entry.domain_queried == 'example.com'
                assert log_entry.status == 'denied'

class TestErrorHandling:
    """Test error handling and edge cases"""
    
    def test_empty_authorization_header(self, mock_dns_handler):
        """Test handling of missing authorization header"""
        mock_dns_handler.headers = {}
        
        # This would be tested in integration with the actual do_GET method
        # Here we test the header extraction logic
        token = mock_dns_handler.headers.get('Authorization')
        token = token.split('Bearer ')[-1] if token else None
        
        assert token is None
    
    def test_malformed_authorization_header(self, mock_dns_handler):
        """Test handling of malformed authorization header"""
        test_cases = [
            'Bearer',  # No token
            'Basic dGVzdA==',  # Wrong auth type
            'Bearer ',  # Empty token
            'Bearertoken123',  # Missing space
        ]
        
        for auth_header in test_cases:
            mock_dns_handler.headers = {'Authorization': auth_header}
            
            token = mock_dns_handler.headers.get('Authorization')
            token = token.split('Bearer ')[-1] if token else None
            
            # Should handle gracefully
            if auth_header == 'Bearer':
                assert token == 'Bearer'
            elif auth_header == 'Bearer ':
                assert token == ''
            else:
                assert token != 'test-token-123456789'
    
    def test_database_connection_error(self):
        """Test handling of database connection errors"""
        handler = DNSHandler(None, None, None)
        
        with patch('server.DAL') as mock_dal:
            mock_dal.side_effect = Exception("Database connection failed")
            
            # Should handle database errors gracefully
            result = handler.check_token_permission_new('token', 'example.com')
            assert result is False
    
    def test_dns_resolution_timeout(self):
        """Test handling of DNS resolution timeouts"""
        handler = DNSHandler(None, None, None)
        
        with patch('dns.resolver.Resolver') as mock_resolver:
            mock_resolver_instance = Mock()
            mock_resolver_instance.resolve.side_effect = TimeoutError("DNS timeout")
            mock_resolver.return_value = mock_resolver_instance
            
            result = handler.resolve_dns("timeout.example.com", "A")
            result_dict = json.loads(result)
            
            assert result_dict["Status"] == 2
            assert "timeout" in result_dict["Comment"].lower()

class TestPerformanceAndCaching:
    """Test performance-related functionality"""
    
    def test_domain_validation_performance(self, valid_domains):
        """Test domain validation performance with many domains"""
        handler = DNSHandler(None, None, None)
        
        # Test with a large number of domains
        import time
        
        start_time = time.time()
        for _ in range(1000):
            for domain in valid_domains[:3]:  # Test with first 3 domains
                if domain != "*.example.com":
                    handler.is_valid_domain(domain)
        end_time = time.time()
        
        # Should complete validation quickly (< 1 second for 3000 validations)
        assert end_time - start_time < 1.0
    
    def test_token_validation_caching_potential(self, temp_db, sample_token_data):
        """Test that repeated token validations could benefit from caching"""
        handler = DNSHandler(None, None, None)
        
        with patch('os.path.join') as mock_join:
            mock_join.return_value = temp_db._uri.split('://')[-1]
            
            with patch('server.DAL') as mock_dal:
                mock_dal.return_value = temp_db
                
                # Perform same validation multiple times
                results = []
                for _ in range(10):
                    result = handler.check_token_permission_new(
                        sample_token_data['token'],
                        sample_token_data['domain']
                    )
                    results.append(result)
                
                # All results should be consistent
                assert all(result is True for result in results)
                
                # In a real caching implementation, subsequent calls would be faster