#!/usr/bin/env python3
"""
Integration tests for API endpoints
Tests the extended API endpoints with actual HTTP requests.
"""

import pytest
import json
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from quart import Quart
from quart.testing import QuartClient
from extended_api_endpoints import ExtendedAPIHandler

class TestAPIIntegration:
    
    @pytest.fixture
    async def api_handler(self, temp_db, test_jwt_secret):
        """Create API handler with test database"""
        db_url = f"sqlite://{temp_db._uri[9:]}"
        handler = ExtendedAPIHandler(db_url, test_jwt_secret)
        
        # Set up security context
        handler.set_security_context(enable_mtls=False)
        
        return handler
    
    @pytest.fixture
    def app(self, api_handler):
        """Create Quart app for testing"""
        app = Quart(__name__)
        
        # Add routes
        @app.route('/whois/lookup', methods=['GET', 'POST'])
        async def whois_lookup():
            return await api_handler.whois_lookup()
        
        @app.route('/whois/search')
        async def whois_search():
            return await api_handler.whois_search()
        
        @app.route('/ioc/check', methods=['GET', 'POST'])
        async def ioc_check():
            return await api_handler.ioc_check()
        
        @app.route('/ioc/overrides', methods=['GET', 'POST', 'DELETE'])
        async def ioc_overrides():
            return await api_handler.ioc_override()
        
        @app.route('/client/config/pull')
        async def config_pull():
            return await api_handler.client_config_pull()
        
        @app.route('/client/register', methods=['POST'])
        async def client_register():
            return await api_handler.client_register()
        
        @app.route('/metrics')
        async def metrics():
            return await api_handler.prometheus_metrics()
        
        @app.route('/stats')
        async def stats():
            return await api_handler.service_stats()
        
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()
    
    @pytest.fixture
    def auth_headers(self, sample_token_data):
        """Create authentication headers"""
        return {
            'Authorization': f'Bearer {sample_token_data["token"]}',
            'Content-Type': 'application/json'
        }
    
    @pytest.mark.asyncio
    async def test_whois_lookup_get_success(self, client, auth_headers):
        """Test WHOIS lookup via GET request"""
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'test.example.com',
                'registrar': 'Test Registrar Inc.',
                'creation_date': datetime(2020, 1, 1),
                'expiration_date': datetime(2025, 1, 1)
            }
            
            response = await client.get(
                '/whois/lookup?domain=test.example.com',
                headers=auth_headers
            )
            
            assert response.status_code == 200
            data = await response.get_json()
            
            assert data['success'] is True
            assert data['domain'] == 'test.example.com'
            assert data['registrar'] == 'Test Registrar Inc.'
    
    @pytest.mark.asyncio
    async def test_whois_lookup_post_success(self, client, auth_headers):
        """Test WHOIS lookup via POST request"""
        with patch('whois.whois') as mock_whois:
            mock_whois.return_value = {
                'domain_name': 'post-test.example.com',
                'registrar': 'Post Test Registrar'
            }
            
            payload = {
                'query': 'post-test.example.com',
                'type': 'domain',
                'force_refresh': False
            }
            
            response = await client.post(
                '/whois/lookup',
                headers=auth_headers,
                json=payload
            )
            
            assert response.status_code == 200
            data = await response.get_json()
            
            assert data['success'] is True
            assert data['domain'] == 'post-test.example.com'
    
    @pytest.mark.asyncio
    async def test_whois_lookup_unauthorized(self, client):
        """Test WHOIS lookup without authentication"""
        response = await client.get('/whois/lookup?domain=test.example.com')
        
        assert response.status_code == 401
        data = await response.get_json()
        assert 'error' in data
    
    @pytest.mark.asyncio
    async def test_whois_lookup_missing_query(self, client, auth_headers):
        """Test WHOIS lookup with missing query parameter"""
        response = await client.get('/whois/lookup', headers=auth_headers)
        
        assert response.status_code == 400
        data = await response.get_json()
        assert 'error' in data
        assert 'required' in data['error'].lower()
    
    @pytest.mark.asyncio
    async def test_whois_search_success(self, client, auth_headers):
        """Test WHOIS search endpoint"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            with patch('whois_manager.WHOISManager.search_whois') as mock_search:
                mock_search.return_value = [
                    {'domain': 'result1.com', 'registrar': 'Test Registrar'},
                    {'domain': 'result2.com', 'registrar': 'Test Registrar'}
                ]
                
                response = await client.get(
                    '/whois/search?q=Test Registrar&field=registrar',
                    headers=auth_headers
                )
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert 'results' in data
                assert data['count'] == 2
                assert data['search_term'] == 'Test Registrar'
                assert data['search_field'] == 'registrar'
    
    @pytest.mark.asyncio
    async def test_ioc_check_get_clean(self, client, auth_headers):
        """Test IOC check for clean domain"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            with patch('ioc_manager.IOCManager.check_domain') as mock_check:
                mock_check.return_value = (False, "Domain not in threat intelligence feeds")
                
                response = await client.get(
                    '/ioc/check?domain=clean.example.com',
                    headers=auth_headers
                )
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert data['query'] == 'clean.example.com'
                assert data['type'] == 'domain'
                assert data['blocked'] is False
    
    @pytest.mark.asyncio
    async def test_ioc_check_post_blocked(self, client, auth_headers):
        """Test IOC check for blocked domain via POST"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            with patch('ioc_manager.IOCManager.check_domain') as mock_check:
                mock_check.return_value = (True, "Domain found in threat intelligence feed: malware")
                
                payload = {
                    'query': 'malware.example.com',
                    'type': 'domain'
                }
                
                response = await client.post(
                    '/ioc/check',
                    headers=auth_headers,
                    json=payload
                )
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert data['blocked'] is True
                assert 'threat intelligence' in data['reason'].lower()
    
    @pytest.mark.asyncio
    async def test_ioc_overrides_get(self, client, auth_headers):
        """Test getting IOC overrides"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            with patch('ioc_manager.IOCManager.get_overrides') as mock_get:
                mock_get.return_value = [
                    {
                        'indicator': 'override.example.com',
                        'type': 'domain',
                        'override_type': 'allow',
                        'reason': 'False positive'
                    }
                ]
                
                response = await client.get('/ioc/overrides', headers=auth_headers)
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert 'overrides' in data
                assert len(data['overrides']) == 1
                assert data['overrides'][0]['indicator'] == 'override.example.com'
    
    @pytest.mark.asyncio
    async def test_ioc_overrides_post(self, client, auth_headers):
        """Test adding IOC override"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1,
                'token_name': 'test-user'
            }
            
            with patch('ioc_manager.IOCManager.add_override') as mock_add:
                mock_add.return_value = True
                
                payload = {
                    'indicator': 'new-override.example.com',
                    'type': 'domain',
                    'override': 'allow',
                    'reason': 'Legitimate business domain'
                }
                
                response = await client.post(
                    '/ioc/overrides',
                    headers=auth_headers,
                    json=payload
                )
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert data['success'] is True
                assert 'Override added' in data['message']
    
    @pytest.mark.asyncio
    async def test_ioc_overrides_delete(self, client, auth_headers):
        """Test removing IOC override"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            with patch('ioc_manager.IOCManager.remove_override') as mock_remove:
                mock_remove.return_value = True
                
                payload = {
                    'indicator': 'remove-override.example.com',
                    'type': 'domain'
                }
                
                response = await client.delete(
                    '/ioc/overrides',
                    headers=auth_headers,
                    json=payload
                )
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert data['success'] is True
                assert 'Override removed' in data['message']
    
    @pytest.mark.asyncio
    async def test_client_config_pull_success(self, client, auth_headers):
        """Test client configuration pull"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1,
                'client_cert_subject': None
            }
            
            with patch('client_config_api.ClientConfigManager.pull_client_config') as mock_pull:
                mock_pull.return_value = {
                    'success': True,
                    'config': {
                        'server_url': 'https://dns.example.com:8443',
                        'dns_port': 53,
                        'cache_enabled': True,
                        'cache_ttl': 300
                    },
                    'version': 1,
                    'config_name': 'default'
                }
                
                response = await client.get(
                    '/client/config/pull?client_id=test-client&domain_jwt=test.jwt.token',
                    headers=auth_headers
                )
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert data['success'] is True
                assert 'config' in data
                assert data['config']['server_url'] == 'https://dns.example.com:8443'
                assert data['version'] == 1
    
    @pytest.mark.asyncio
    async def test_client_config_pull_missing_params(self, client, auth_headers):
        """Test client config pull with missing parameters"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            response = await client.get(
                '/client/config/pull?client_id=test-client',  # Missing domain_jwt
                headers=auth_headers
            )
            
            assert response.status_code == 400
            data = await response.get_json()
            assert 'required' in data['error'].lower()
    
    @pytest.mark.asyncio
    async def test_client_register_success(self, client, auth_headers):
        """Test client registration"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1,
                'client_cert_subject': None
            }
            
            with patch('client_config_api.ClientConfigManager.register_client') as mock_register:
                mock_register.return_value = {
                    'success': True,
                    'client_record_id': 123,
                    'domain_name': 'test-domain'
                }
                
                payload = {
                    'client_id': 'register-test-client',
                    'domain_jwt': 'test.domain.jwt',
                    'hostname': 'test-hostname',
                    'ip_address': '192.168.1.100',
                    'client_version': 'v2.0.0',
                    'os_info': 'Linux Ubuntu 22.04'
                }
                
                response = await client.post(
                    '/client/register',
                    headers=auth_headers,
                    json=payload
                )
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert data['success'] is True
                assert data['client_record_id'] == 123
                assert data['domain_name'] == 'test-domain'
    
    @pytest.mark.asyncio
    async def test_prometheus_metrics_endpoint(self, client):
        """Test Prometheus metrics endpoint"""
        with patch('prometheus_metrics.get_metrics_instance') as mock_get_metrics:
            mock_prometheus = Mock()
            mock_prometheus.get_metrics_endpoint.return_value = (
                b"# HELP squawk_dns_queries_total Total DNS queries\nSquawk_dns_queries_total 100\n",
                'text/plain; version=0.0.4; charset=utf-8'
            )
            mock_get_metrics.return_value = mock_prometheus
            
            response = await client.get('/metrics')
            
            assert response.status_code == 200
            
            # Check content type
            content_type = response.headers.get('Content-Type', '')
            assert 'text/plain' in content_type
    
    @pytest.mark.asyncio
    async def test_metrics_with_auth_token(self, client, auth_headers):
        """Test metrics endpoint with authentication token"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'metrics-token'
            }
            
            with patch('prometheus_metrics.get_metrics_instance') as mock_get_metrics:
                mock_prometheus = Mock()
                mock_prometheus.get_metrics_endpoint.return_value = (
                    b"# Authenticated metrics\n",
                    'text/plain; version=0.0.4; charset=utf-8'
                )
                mock_get_metrics.return_value = mock_prometheus
                
                headers = auth_headers.copy()
                headers['X-Metrics-Token'] = 'metrics-token-123'
                
                response = await client.get('/metrics', headers=headers)
                
                assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_service_stats_success(self, client, auth_headers):
        """Test service statistics endpoint"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            # Mock all stats methods
            with patch('whois_manager.WHOISManager.get_stats') as mock_whois_stats, \
                 patch('ioc_manager.IOCManager.get_stats') as mock_ioc_stats, \
                 patch('client_config_api.ClientConfigManager.get_client_stats') as mock_config_stats:
                
                mock_whois_stats.return_value = {
                    'queries': {'total': 100, 'domain_queries': 80, 'ip_queries': 20},
                    'cache': {'total_entries': 50, 'hit_rate': 0.75}
                }
                
                mock_ioc_stats.return_value = {
                    'feeds': {'total': 5, 'enabled': 4},
                    'indicators': {'total': 10000, 'domains': 8000, 'ips': 2000}
                }
                
                mock_config_stats.return_value = {
                    'clients': {'total': 25, 'active': 20},
                    'domains': {'total': 3, 'active': 3}
                }
                
                response = await client.get('/stats', headers=auth_headers)
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert 'timestamp' in data
                assert 'services' in data
                
                assert 'whois' in data['services']
                assert 'ioc' in data['services']
                assert 'client_config' in data['services']
                
                assert data['services']['whois']['queries']['total'] == 100
                assert data['services']['ioc']['feeds']['total'] == 5
                assert data['services']['client_config']['clients']['total'] == 25
    
    @pytest.mark.asyncio
    async def test_error_handling_network_timeout(self, client, auth_headers):
        """Test API error handling for network timeouts"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            with patch('whois.whois') as mock_whois:
                import socket
                mock_whois.side_effect = socket.timeout("Connection timed out")
                
                response = await client.get(
                    '/whois/lookup?domain=timeout.example.com',
                    headers=auth_headers
                )
                
                assert response.status_code == 500
                data = await response.get_json()
                assert 'error' in data
    
    @pytest.mark.asyncio
    async def test_invalid_json_payload(self, client, auth_headers):
        """Test handling of invalid JSON payloads"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            # Send invalid JSON
            response = await client.post(
                '/ioc/overrides',
                headers={'Authorization': auth_headers['Authorization'], 'Content-Type': 'application/json'},
                data='{"invalid": json payload}'  # Invalid JSON
            )
            
            # Should handle gracefully
            assert response.status_code in [400, 500]  # Either is acceptable
    
    @pytest.mark.asyncio
    async def test_concurrent_api_requests(self, client, auth_headers):
        """Test concurrent API requests"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            with patch('ioc_manager.IOCManager.check_domain') as mock_check:
                mock_check.return_value = (False, "Clean domain")
                
                # Make multiple concurrent requests
                tasks = []
                for i in range(10):
                    task = client.get(
                        f'/ioc/check?domain=concurrent{i}.example.com',
                        headers=auth_headers
                    )
                    tasks.append(task)
                
                responses = await asyncio.gather(*tasks)
                
                # All should succeed
                assert len(responses) == 10
                for response in responses:
                    assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_rate_limiting_behavior(self, client, auth_headers):
        """Test API rate limiting behavior if implemented"""
        # This test assumes rate limiting might be implemented
        # For now, just test that rapid requests work
        
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            with patch('ioc_manager.IOCManager.check_domain') as mock_check:
                mock_check.return_value = (False, "Clean domain")
                
                # Make rapid requests
                responses = []
                for i in range(20):
                    response = await client.get(
                        f'/ioc/check?domain=rate{i}.example.com',
                        headers=auth_headers
                    )
                    responses.append(response)
                
                # All should succeed (no rate limiting currently)
                success_count = sum(1 for r in responses if r.status_code == 200)
                assert success_count >= 15  # Allow for some potential rate limiting
    
    @pytest.mark.asyncio
    async def test_mtls_certificate_handling(self, client, auth_headers):
        """Test mTLS certificate handling"""
        # Create API handler with mTLS enabled
        api_handler = ExtendedAPIHandler("sqlite:///:memory:", "test-secret")
        api_handler.set_security_context(enable_mtls=True)
        
        app = Quart(__name__)
        
        @app.route('/client/config/pull')
        async def config_pull():
            return await api_handler.client_config_pull()
        
        test_client = app.test_client()
        
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1,
                'client_cert_subject': 'CN=test-client,O=Test Org'
            }
            
            with patch('client_config_api.ClientConfigManager.pull_client_config') as mock_pull:
                mock_pull.return_value = {
                    'success': True,
                    'config': {'server_url': 'https://dns.example.com'},
                    'version': 1
                }
                
                # Headers that would be set by reverse proxy for mTLS
                headers = auth_headers.copy()
                headers['X-SSL-Client-S-DN'] = 'CN=test-client,O=Test Org'
                headers['X-SSL-Client-Verify'] = 'SUCCESS'
                
                response = await test_client.get(
                    '/client/config/pull?client_id=test&domain_jwt=test.jwt',
                    headers=headers
                )
                
                assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_large_response_handling(self, client, auth_headers):
        """Test handling of large API responses"""
        with patch.object(ExtendedAPIHandler, '_authenticate_request') as mock_auth:
            mock_auth.return_value = {
                'authenticated': True,
                'token': 'test-token',
                'token_id': 1
            }
            
            # Mock large WHOIS search result
            large_results = []
            for i in range(1000):  # Large result set
                large_results.append({
                    'domain': f'result{i}.example.com',
                    'registrar': f'Registrar {i % 10}',
                    'created': '2020-01-01'
                })
            
            with patch('whois_manager.WHOISManager.search_whois') as mock_search:
                mock_search.return_value = large_results
                
                response = await client.get(
                    '/whois/search?q=example&limit=1000',
                    headers=auth_headers
                )
                
                assert response.status_code == 200
                data = await response.get_json()
                
                assert data['count'] == 1000
                assert len(data['results']) == 1000