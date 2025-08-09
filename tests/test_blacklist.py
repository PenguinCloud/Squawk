#!/usr/bin/env python3
"""
Unit tests for blacklist functionality
"""

import pytest
import asyncio
import sys
import os
from unittest.mock import Mock, patch, AsyncMock

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'dns-server', 'bins'))

from server_optimized import BlacklistManager

class TestBlacklistManager:
    """Test the BlacklistManager class"""
    
    @pytest.fixture
    def blacklist_manager(self):
        """Create a BlacklistManager instance for testing"""
        with patch.dict(os.environ, {'ENABLE_BLACKLIST': 'false'}):
            manager = BlacklistManager()
            # Don't start the updater in tests
            return manager
    
    def test_is_blocked_domain(self, blacklist_manager):
        """Test domain blocking"""
        # Add test domains
        blacklist_manager.custom_blocked_domains.add('evil.com')
        blacklist_manager.custom_blocked_domains.add('badsite.org')
        
        # Test exact match
        assert blacklist_manager.is_blocked('evil.com')
        assert blacklist_manager.is_blocked('badsite.org')
        
        # Test subdomain blocking
        assert blacklist_manager.is_blocked('sub.evil.com')
        assert blacklist_manager.is_blocked('deep.sub.evil.com')
        
        # Test non-blocked domains
        assert not blacklist_manager.is_blocked('good.com')
        assert not blacklist_manager.is_blocked('example.org')
    
    def test_is_blocked_ip(self, blacklist_manager):
        """Test IP blocking"""
        # Add test IPs
        blacklist_manager.custom_blocked_ips.add('192.168.1.100')
        blacklist_manager.custom_blocked_ips.add('10.0.0.5')
        
        # Test IP blocking
        assert blacklist_manager.is_blocked('example.com', '192.168.1.100')
        assert blacklist_manager.is_blocked('example.com', '10.0.0.5')
        
        # Test non-blocked IPs
        assert not blacklist_manager.is_blocked('example.com', '8.8.8.8')
        assert not blacklist_manager.is_blocked('example.com', '1.1.1.1')
    
    def test_case_insensitive_blocking(self, blacklist_manager):
        """Test that blocking is case-insensitive"""
        blacklist_manager.custom_blocked_domains.add('evil.com')
        
        assert blacklist_manager.is_blocked('EVIL.COM')
        assert blacklist_manager.is_blocked('Evil.Com')
        assert blacklist_manager.is_blocked('eViL.cOm')
    
    @pytest.mark.asyncio
    async def test_update_maravento_blacklist(self, blacklist_manager):
        """Test Maravento blacklist update"""
        mock_response = Mock()
        mock_response.content = b'test content'
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            with patch('tarfile.open'):
                with patch('aiofiles.open', create=True) as mock_open:
                    mock_open.return_value.__aenter__.return_value.read = AsyncMock(
                        return_value='evil1.com\nevil2.com\n#comment\nevil3.com'
                    )
                    
                    await blacklist_manager.update_maravento_blacklist()
        
        # Check that domains were loaded
        assert 'evil1.com' in blacklist_manager.blocked_domains
        assert 'evil2.com' in blacklist_manager.blocked_domains
        assert 'evil3.com' in blacklist_manager.blocked_domains
        assert '#comment' not in blacklist_manager.blocked_domains
    
    def test_load_custom_blacklists(self, blacklist_manager):
        """Test loading custom blacklists from database"""
        # This would require mocking the database
        # For now, just ensure the method exists and doesn't crash
        blacklist_manager.load_custom_blacklists()
        assert True  # If we get here, no exceptions were raised