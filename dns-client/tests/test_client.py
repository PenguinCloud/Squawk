"""
Unit tests for DNS client functionality
"""
import pytest
import json
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import requests
import socket
import threading
import time

# Add the bins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bins'))

# Import the client module
import client
from client import DNSOverHTTPSClient, DNSForwarder

class TestDNSOverHTTPSClient:
    """Test DNS-over-HTTPS client functionality"""
    
    def test_client_initialization(self):
        """Test client initialization with parameters"""
        dns_server_url = "https://dns.example.com:8443"
        auth_token = "test-token-123"
        
        client_instance = DNSOverHTTPSClient(dns_server_url, auth_token)
        
        assert client_instance.dns_server_url == dns_server_url
        assert client_instance.auth_token == auth_token
    
    def test_client_initialization_defaults(self):
        """Test client initialization with default values"""
        client_instance = DNSOverHTTPSClient()
        
        assert client_instance.dns_server_url == "https://dns.google/dns-query"
        assert client_instance.auth_token is None
    
    @patch('requests.get')
    def test_successful_dns_query(self, mock_get, mock_response):
        """Test successful DNS query"""
        mock_get.return_value = mock_response
        
        client_instance = DNSOverHTTPSClient(
            "https://dns.example.com:8443", 
            "test-token-123"
        )
        
        result = client_instance.query("example.com", "A")
        
        # Verify request was made correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        
        assert "name=example.com" in call_args[1]['params']['name']
        assert call_args[1]['params']['type'] == "A"
        assert call_args[1]['headers']['Authorization'] == "Bearer test-token-123"
        
        # Verify response
        assert result['Status'] == 0
        assert result['Answer'][0]['data'] == "93.184.216.34"
    
    @patch('requests.get')
    def test_dns_query_without_auth(self, mock_get, mock_response):
        """Test DNS query without authentication token"""
        mock_get.return_value = mock_response
        
        client_instance = DNSOverHTTPSClient("https://dns.example.com:8443")
        
        result = client_instance.query("example.com", "A")
        
        # Verify no Authorization header is sent when no token
        call_args = mock_get.call_args
        assert 'Authorization' not in call_args[1]['headers']
    
    @patch('requests.get')
    def test_dns_query_authentication_failure(self, mock_get, mock_error_response):
        """Test DNS query with authentication failure"""
        mock_get.return_value = mock_error_response
        
        client_instance = DNSOverHTTPSClient(
            "https://dns.example.com:8443", 
            "invalid-token"
        )
        
        with pytest.raises(Exception, match="Authentication failed"):
            client_instance.query("example.com", "A")
    
    @patch('requests.get')
    def test_dns_query_network_error(self, mock_get):
        """Test DNS query with network error"""
        mock_get.side_effect = requests.exceptions.ConnectionError("Network error")
        
        client_instance = DNSOverHTTPSClient(
            "https://dns.example.com:8443", 
            "test-token-123"
        )
        
        with pytest.raises(requests.exceptions.ConnectionError):
            client_instance.query("example.com", "A")
    
    @patch('requests.get')
    def test_dns_query_different_record_types(self, mock_get, dns_query_samples):
        """Test DNS queries for different record types"""
        client_instance = DNSOverHTTPSClient(
            "https://dns.example.com:8443", 
            "test-token-123"
        )
        
        for record_type, sample in dns_query_samples.items():
            # Mock response for this record type
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "Status": 0,
                "Answer": [{
                    "name": sample['domain'],
                    "type": record_type,
                    "data": sample.get('expected_ip', sample.get('expected_data', 'test-data'))
                }]
            }
            mock_get.return_value = mock_response
            
            result = client_instance.query(sample['domain'], record_type)
            
            assert result['Status'] == 0
            assert result['Answer'][0]['type'] == record_type
            assert result['Answer'][0]['name'] == sample['domain']
    
    @patch('requests.get')
    def test_dns_query_timeout(self, mock_get):
        """Test DNS query timeout handling"""
        mock_get.side_effect = requests.exceptions.Timeout("Query timeout")
        
        client_instance = DNSOverHTTPSClient(
            "https://dns.example.com:8443", 
            "test-token-123"
        )
        
        with pytest.raises(requests.exceptions.Timeout):
            client_instance.query("example.com", "A")

class TestDNSForwarder:
    """Test DNS forwarding functionality"""
    
    def test_forwarder_initialization(self):
        """Test DNS forwarder initialization"""
        dns_client = DNSOverHTTPSClient()
        forwarder = DNSForwarder(
            dns_client, 
            udp_port=5353, 
            tcp_port=5353,
            listen_udp=True, 
            listen_tcp=True
        )
        
        assert forwarder.dns_client == dns_client
        assert forwarder.udp_port == 5353
        assert forwarder.tcp_port == 5353
        assert forwarder.listen_udp is True
        assert forwarder.listen_tcp is True
    
    def test_forwarder_default_initialization(self):
        """Test DNS forwarder with default parameters"""
        dns_client = DNSOverHTTPSClient()
        forwarder = DNSForwarder(dns_client)
        
        assert forwarder.udp_port == 53
        assert forwarder.tcp_port == 53
        assert forwarder.listen_udp is False
        assert forwarder.listen_tcp is False
    
    @patch('socket.socket')
    @patch('threading.Thread')
    def test_start_udp_only(self, mock_thread, mock_socket_class):
        """Test starting UDP server only"""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        dns_client = DNSOverHTTPSClient()
        forwarder = DNSForwarder(dns_client, listen_udp=True, listen_tcp=False)
        
        # Mock threading to prevent actual server start
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        
        forwarder.start()
        
        # Verify only UDP thread was created
        assert mock_thread.call_count == 1
        mock_thread.assert_called_with(target=forwarder.start_udp_server)
    
    @patch('socket.socket')
    @patch('threading.Thread')
    def test_start_tcp_only(self, mock_thread, mock_socket_class):
        """Test starting TCP server only"""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        dns_client = DNSOverHTTPSClient()
        forwarder = DNSForwarder(dns_client, listen_udp=False, listen_tcp=True)
        
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        
        forwarder.start()
        
        # Verify only TCP thread was created
        assert mock_thread.call_count == 1
        mock_thread.assert_called_with(target=forwarder.start_tcp_server)
    
    @patch('socket.socket')
    def test_udp_server_setup(self, mock_socket_class, mock_socket):
        """Test UDP server setup"""
        mock_socket_class.return_value = mock_socket
        
        dns_client = DNSOverHTTPSClient()
        forwarder = DNSForwarder(dns_client, udp_port=5353)
        
        # Mock the infinite loop to prevent hanging
        with patch('builtins.iter', side_effect=StopIteration):
            try:
                forwarder.start_udp_server()
            except StopIteration:
                pass
        
        # Verify socket setup
        mock_socket_class.assert_called_with(socket.AF_INET, socket.SOCK_DGRAM)
        mock_socket.bind.assert_called_with(("127.0.0.1", 5353))
    
    @patch('socket.socket')
    def test_tcp_server_setup(self, mock_socket_class, mock_socket):
        """Test TCP server setup"""
        mock_socket_class.return_value = mock_socket
        
        dns_client = DNSOverHTTPSClient()
        forwarder = DNSForwarder(dns_client, tcp_port=5353)
        
        # Mock the infinite loop to prevent hanging
        with patch('builtins.iter', side_effect=StopIteration):
            try:
                forwarder.start_tcp_server()
            except StopIteration:
                pass
        
        # Verify socket setup
        mock_socket_class.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket.bind.assert_called_with(("127.0.0.1", 5353))
        mock_socket.listen.assert_called_with(5)
    
    def test_handle_request_placeholder(self):
        """Test request handling placeholder functionality"""
        dns_client = DNSOverHTTPSClient()
        forwarder = DNSForwarder(dns_client)
        
        # Test the placeholder implementation
        result = forwarder.handle_request(b'fake_dns_query')
        
        # Current implementation returns empty response
        assert result == b""

class TestConfigurationHandling:
    """Test configuration file handling"""
    
    def test_load_config_success(self, temp_config_file, sample_config):
        """Test loading valid configuration file"""
        config = client.load_config(temp_config_file)
        
        assert config['domain'] == sample_config['domain']
        assert config['server'] == sample_config['server']
        assert config['auth'] == sample_config['auth']
    
    def test_load_config_nonexistent_file(self):
        """Test loading non-existent configuration file"""
        with pytest.raises(FileNotFoundError):
            client.load_config('/path/to/nonexistent/config.yml')
    
    def test_load_config_malformed_yaml(self):
        """Test loading malformed YAML configuration"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as tmp:
            tmp.write("invalid: yaml: content: [")
            tmp_path = tmp.name
        
        try:
            with pytest.raises(yaml.YAMLError):
                client.load_config(tmp_path)
        finally:
            os.unlink(tmp_path)

class TestMainFunction:
    """Test main function and command-line argument parsing"""
    
    def test_main_argument_parsing_minimal(self):
        """Test main function with minimal arguments"""
        test_args = ['-d', 'example.com']
        
        with patch('client.DNSOverHTTPSClient') as mock_client_class:
            with patch('client.DNSForwarder') as mock_forwarder_class:
                mock_client = Mock()
                mock_client.query.return_value = {"Status": 0, "Answer": []}
                mock_client_class.return_value = mock_client
                
                mock_forwarder = Mock()
                mock_forwarder_class.return_value = mock_forwarder
                
                try:
                    client.main(test_args)
                except SystemExit:
                    pass  # Expected when forwarder.start() is called
                
                # Verify client was created with correct parameters
                mock_client_class.assert_called_once()
                call_args = mock_client_class.call_args[0]
                assert call_args[0] == "https://dns.google/resolve"  # Default server
                assert call_args[1] is None  # No auth token
    
    def test_main_argument_parsing_full(self):
        """Test main function with all arguments"""
        test_args = [
            '-d', 'example.com',
            '-t', 'AAAA',
            '-s', 'https://custom.dns.server',
            '-a', 'auth-token-123',
            '-u',  # UDP
            '-T'   # TCP
        ]
        
        with patch('client.DNSOverHTTPSClient') as mock_client_class:
            with patch('client.DNSForwarder') as mock_forwarder_class:
                mock_client = Mock()
                mock_client.query.return_value = {"Status": 0, "Answer": []}
                mock_client_class.return_value = mock_client
                
                mock_forwarder = Mock()
                mock_forwarder_class.return_value = mock_forwarder
                
                try:
                    client.main(test_args)
                except SystemExit:
                    pass
                
                # Verify client creation
                call_args = mock_client_class.call_args[0]
                assert call_args[0] == "https://custom.dns.server"
                assert call_args[1] == "auth-token-123"
                
                # Verify query execution
                mock_client.query.assert_called_with('example.com', 'AAAA')
                
                # Verify forwarder creation with UDP and TCP enabled
                forwarder_call_args = mock_forwarder_class.call_args
                assert forwarder_call_args[1]['listen_udp'] is True
                assert forwarder_call_args[1]['listen_tcp'] is True
    
    def test_main_with_config_file(self, temp_config_file):
        """Test main function with configuration file"""
        test_args = ['-c', temp_config_file]
        
        with patch('client.DNSOverHTTPSClient') as mock_client_class:
            with patch('client.DNSForwarder') as mock_forwarder_class:
                mock_client = Mock()
                mock_client.query.return_value = {"Status": 0, "Answer": []}
                mock_client_class.return_value = mock_client
                
                mock_forwarder = Mock()
                mock_forwarder_class.return_value = mock_forwarder
                
                try:
                    client.main(test_args)
                except SystemExit:
                    pass
                
                # Verify client was created with config file values
                call_args = mock_client_class.call_args[0]
                assert call_args[0] == "https://dns.example.com:8443"
                assert call_args[1] == "test-token-123456789"
                
                # Verify query was made with config values
                mock_client.query.assert_called_with('example.com', 'A')
    
    def test_main_config_override_by_args(self, temp_config_file):
        """Test that command-line arguments override config file values"""
        test_args = [
            '-c', temp_config_file,
            '-d', 'override.com',  # Override domain from config
            '-t', 'MX'             # Override type from config
        ]
        
        with patch('client.DNSOverHTTPSClient') as mock_client_class:
            with patch('client.DNSForwarder') as mock_forwarder_class:
                mock_client = Mock()
                mock_client.query.return_value = {"Status": 0, "Answer": []}
                mock_client_class.return_value = mock_client
                
                mock_forwarder = Mock()
                mock_forwarder_class.return_value = mock_forwarder
                
                try:
                    client.main(test_args)
                except SystemExit:
                    pass
                
                # Verify query uses overridden values
                mock_client.query.assert_called_with('override.com', 'MX')
    
    def test_main_missing_domain(self):
        """Test main function with missing required domain"""
        test_args = []  # No domain specified
        
        with pytest.raises(SystemExit):
            client.main(test_args)
    
    def test_main_help_option(self):
        """Test main function with help option"""
        test_args = ['-h']
        
        with pytest.raises(SystemExit):
            client.main(test_args)

class TestErrorHandling:
    """Test error handling and edge cases"""
    
    def test_client_with_invalid_url(self):
        """Test client with invalid server URL"""
        with pytest.raises(requests.exceptions.RequestException):
            client_instance = DNSOverHTTPSClient("invalid-url", "token")
            
            with patch('requests.get', side_effect=requests.exceptions.InvalidURL("Invalid URL")):
                client_instance.query("example.com", "A")
    
    def test_forwarder_socket_binding_error(self):
        """Test forwarder with socket binding error"""
        dns_client = DNSOverHTTPSClient()
        forwarder = DNSForwarder(dns_client, udp_port=80)  # Privileged port
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.bind.side_effect = PermissionError("Permission denied")
            mock_socket_class.return_value = mock_socket
            
            with pytest.raises(PermissionError):
                forwarder.start_udp_server()
    
    def test_client_json_parsing_error(self):
        """Test client with JSON parsing error"""
        client_instance = DNSOverHTTPSClient("https://dns.example.com", "token")
        
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
            mock_get.return_value = mock_response
            
            with pytest.raises(json.JSONDecodeError):
                client_instance.query("example.com", "A")

class TestSecurityFeatures:
    """Test security-related functionality"""
    
    def test_secure_token_handling(self):
        """Test that tokens are handled securely"""
        client_instance = DNSOverHTTPSClient(
            "https://dns.example.com", 
            "sensitive-token-123"
        )
        
        # Token should be stored but not logged or exposed
        assert client_instance.auth_token == "sensitive-token-123"
        
        # Verify token is passed correctly in headers
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"Status": 0, "Answer": []}
            mock_get.return_value = mock_response
            
            client_instance.query("example.com", "A")
            
            call_args = mock_get.call_args
            assert call_args[1]['headers']['Authorization'] == "Bearer sensitive-token-123"
    
    def test_input_validation_domains(self, invalid_domains):
        """Test that invalid domains are handled properly"""
        client_instance = DNSOverHTTPSClient("https://dns.example.com", "token")
        
        # The client should pass domains to the server for validation
        # but shouldn't crash on invalid input
        for invalid_domain in invalid_domains:
            with patch('requests.get') as mock_get:
                mock_response = Mock()
                mock_response.status_code = 400  # Bad request for invalid domain
                mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Bad Request")
                mock_get.return_value = mock_response
                
                with pytest.raises(requests.exceptions.HTTPError):
                    client_instance.query(invalid_domain, "A")

class TestIntegrationScenarios:
    """Test integration scenarios and workflows"""
    
    @patch('requests.get')
    def test_full_dns_resolution_workflow(self, mock_get, mock_response):
        """Test complete DNS resolution workflow"""
        mock_get.return_value = mock_response
        
        # Create client
        client_instance = DNSOverHTTPSClient(
            "https://dns.example.com:8443",
            "production-token"
        )
        
        # Perform query
        result = client_instance.query("www.example.com", "A")
        
        # Verify complete workflow
        assert result is not None
        assert result["Status"] == 0
        assert len(result["Answer"]) > 0
        assert result["Answer"][0]["name"] == "example.com"
        assert result["Answer"][0]["data"] == "93.184.216.34"
        
        # Verify proper request was made
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert call_args[1]['params']['name'] == "www.example.com"
        assert call_args[1]['params']['type'] == "A"
        assert "production-token" in call_args[1]['headers']['Authorization']
    
    def test_forwarder_integration_setup(self):
        """Test DNS forwarder integration setup"""
        # Create client for remote DNS server
        dns_client = DNSOverHTTPSClient(
            "https://secure-dns.company.com",
            "company-internal-token"
        )
        
        # Create forwarder for local network
        forwarder = DNSForwarder(
            dns_client,
            udp_port=53,
            tcp_port=53,
            listen_udp=True,
            listen_tcp=True
        )
        
        # Verify setup
        assert forwarder.dns_client.dns_server_url == "https://secure-dns.company.com"
        assert forwarder.dns_client.auth_token == "company-internal-token"
        assert forwarder.listen_udp is True
        assert forwarder.listen_tcp is True