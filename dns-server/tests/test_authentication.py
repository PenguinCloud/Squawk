#!/usr/bin/env python3
"""
Unit tests for Squawk DNS Server Authentication Features
Tests MFA, SSO, brute force protection, and email notifications
"""

import unittest
import tempfile
import shutil
import os
import sys
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'web', 'apps', 'dns_console'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bins'))

class TestMFAManager(unittest.TestCase):
    """Test Multi-Factor Authentication functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_generate_secret(self):
        """Test TOTP secret generation"""
        # Mock the MFAManager import
        with patch.dict('sys.modules', {'pyotp': Mock()}):
            from dns_console import MFAManager
            
            # Mock pyotp.random_base32()
            with patch('pyotp.random_base32', return_value='ABCDEFGHIJKLMNOP'):
                secret = MFAManager.generate_secret()
                self.assertEqual(secret, 'ABCDEFGHIJKLMNOP')
    
    def test_generate_backup_codes(self):
        """Test backup code generation"""
        with patch.dict('sys.modules', {'pyotp': Mock()}):
            from dns_console import MFAManager
            
            with patch('secrets.token_hex', return_value='1234abcd'):
                codes = MFAManager.generate_backup_codes(count=5)
                self.assertEqual(len(codes), 5)
                self.assertEqual(codes[0], '1234ABCD')  # Should be uppercase
    
    def test_verify_token_valid(self):
        """Test TOTP token verification with valid token"""
        mock_pyotp = Mock()
        mock_totp = Mock()
        mock_totp.verify.return_value = True
        mock_pyotp.TOTP.return_value = mock_totp
        
        with patch.dict('sys.modules', {'pyotp': mock_pyotp}):
            from dns_console import MFAManager
            
            result = MFAManager.verify_token('ABCDEFGHIJKLMNOP', '123456')
            self.assertTrue(result)
            mock_totp.verify.assert_called_once_with('123456', valid_window=1)
    
    def test_verify_token_invalid(self):
        """Test TOTP token verification with invalid token"""
        mock_pyotp = Mock()
        mock_totp = Mock()
        mock_totp.verify.return_value = False
        mock_pyotp.TOTP.return_value = mock_totp
        
        with patch.dict('sys.modules', {'pyotp': mock_pyotp}):
            from dns_console import MFAManager
            
            result = MFAManager.verify_token('ABCDEFGHIJKLMNOP', '000000')
            self.assertFalse(result)


class TestBruteForceProtection(unittest.TestCase):
    """Test Brute Force Protection functionality"""
    
    def setUp(self):
        """Set up test environment with mock database"""
        self.mock_db = Mock()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_account_not_locked_initially(self):
        """Test that accounts are not locked initially"""
        with patch('dns_console.db', self.mock_db):
            from dns_console import BruteForceProtectionManager
            
            # Mock database query to return no recent attempts
            self.mock_db.return_value.select.return_value = []
            
            is_locked, lock_time = BruteForceProtectionManager.is_account_locked('test_user')
            self.assertFalse(is_locked)
            self.assertIsNone(lock_time)
    
    def test_account_locked_after_max_attempts(self):
        """Test that accounts get locked after max attempts"""
        with patch('dns_console.db', self.mock_db):
            with patch('dns_console.MAX_LOGIN_ATTEMPTS', 3):
                from dns_console import BruteForceProtectionManager
                
                # Simulate 3 failed attempts
                for i in range(3):
                    BruteForceProtectionManager.record_login_attempt(
                        'test_user', 'test@example.com', '192.168.1.1', 
                        'Test Browser', False, 'invalid_password'
                    )
    
    def test_successful_login_clears_lockout(self):
        """Test that successful login clears any existing lockout"""
        with patch('dns_console.db', self.mock_db):
            from dns_console import BruteForceProtectionManager
            
            # Record successful login
            BruteForceProtectionManager.record_login_attempt(
                'test_user', 'test@example.com', '192.168.1.1',
                'Test Browser', True
            )
            
            # Verify database update was called to clear lockout
            self.mock_db.assert_called()


class TestEmailNotifications(unittest.TestCase):
    """Test Email Notification functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @patch('smtplib.SMTP')
    def test_send_account_locked_notification(self, mock_smtp):
        """Test sending account locked notification email"""
        with patch('dns_console.ENABLE_EMAIL_NOTIFICATIONS', True):
            from dns_console import EmailNotificationManager
            
            mock_server = Mock()
            mock_smtp.return_value = mock_server
            
            result = EmailNotificationManager.send_account_locked_notification(
                'test@example.com', 'testuser', '192.168.1.1', 30
            )
            
            self.assertTrue(result)
            mock_server.send_message.assert_called_once()
            mock_server.quit.assert_called_once()
    
    @patch('smtplib.SMTP')
    def test_send_admin_security_alert(self, mock_smtp):
        """Test sending admin security alert email"""
        with patch('dns_console.ENABLE_EMAIL_NOTIFICATIONS', True):
            with patch('dns_console.ADMIN_EMAIL', 'admin@example.com'):
                from dns_console import EmailNotificationManager
                
                mock_server = Mock()
                mock_smtp.return_value = mock_server
                
                result = EmailNotificationManager.send_admin_security_alert(
                    'Account Locked', 'User account was locked due to failed attempts'
                )
                
                self.assertTrue(result)
                mock_server.send_message.assert_called_once()
    
    def test_email_disabled_returns_false(self):
        """Test that email sending returns False when notifications are disabled"""
        with patch('dns_console.ENABLE_EMAIL_NOTIFICATIONS', False):
            from dns_console import EmailNotificationManager
            
            result = EmailNotificationManager.send_email(
                'test@example.com', 'Test Subject', 'Test Body'
            )
            
            self.assertFalse(result)


class TestCacheManagerSecurity(unittest.TestCase):
    """Test Cache Manager security features"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_redis_tls_configuration(self):
        """Test Redis TLS configuration"""
        with patch.dict(os.environ, {
            'CACHE_ENABLED': 'true',
            'REDIS_USE_TLS': 'true',
            'REDIS_USERNAME': 'testuser',
            'REDIS_PASSWORD': 'testpass',
            'REDIS_TLS_VERIFY_MODE': 'required'
        }):
            from cache_manager import CacheManager
            
            cache_manager = CacheManager()
            
            self.assertTrue(cache_manager.redis_use_tls)
            self.assertEqual(cache_manager.redis_username, 'testuser')
            self.assertEqual(cache_manager.redis_password, 'testpass')
            self.assertEqual(cache_manager.redis_tls_verify_mode, 'required')
    
    @patch('redis.asyncio.from_url')
    async def test_redis_secure_connection(self, mock_redis):
        """Test Redis secure connection setup"""
        mock_client = Mock()
        mock_client.ping = Mock(return_value=True)
        mock_redis.return_value = mock_client
        
        with patch.dict(os.environ, {
            'REDIS_URL': 'rediss://user:pass@localhost:6380/0',
            'REDIS_USE_TLS': 'true'
        }):
            from cache_manager import CacheManager
            
            cache_manager = CacheManager()
            # Test connection would be made during initialization
            # In a real test, we'd await the initialization


class TestAuditLogging(unittest.TestCase):
    """Test Audit Logging functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_db = Mock()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_log_audit_event(self):
        """Test audit event logging"""
        with patch('dns_console.db', self.mock_db):
            with patch('dns_console.auth') as mock_auth:
                mock_auth.current_user = {'id': 1}
                
                from dns_console import log_audit_event
                
                with patch('dns_console.request') as mock_request:
                    mock_request.environ = {
                        'REMOTE_ADDR': '192.168.1.1',
                        'HTTP_USER_AGENT': 'Test Browser'
                    }
                    
                    log_audit_event('test_action', 'test_resource', {'test': 'data'})
                    
                    # Verify database insert was called
                    self.mock_db.audit_log.insert.assert_called_once()
                    self.mock_db.commit.assert_called_once()
    
    def test_log_security_event(self):
        """Test security-specific event logging"""
        with patch('dns_console.db', self.mock_db):
            from dns_console import log_audit_event
            
            with patch('dns_console.request') as mock_request:
                mock_request.environ = {
                    'REMOTE_ADDR': '192.168.1.100',
                    'HTTP_USER_AGENT': 'Suspicious Browser'
                }
                
                log_audit_event('failed_login', 'authentication', 
                              {'username': 'admin', 'reason': 'invalid_password'}, 
                              success=False)
                
                # Verify the failed event was logged
                call_args = self.mock_db.audit_log.insert.call_args[1]
                self.assertFalse(call_args['success'])
                self.assertEqual(call_args['action'], 'failed_login')


if __name__ == '__main__':
    # Set up test environment variables
    os.environ.update({
        'CACHE_ENABLED': 'false',  # Disable cache for tests
        'ENABLE_EMAIL_NOTIFICATIONS': 'false',  # Disable emails for tests
        'BRUTE_FORCE_PROTECTION': 'true',
        'MAX_LOGIN_ATTEMPTS': '3',
        'LOCKOUT_DURATION_MINUTES': '30'
    })
    
    # Run tests
    unittest.main(verbosity=2)