#!/usr/bin/env python3
"""
IOC (Indicators of Compromise) Manager for Squawk DNS
Implements threat intelligence blocking with multiple feed sources.
Addresses Issues #15 and #16: IOC blocking and API management
"""

import asyncio
import aiofiles
import aiohttp
import json
import logging
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from pydal import DAL, Field
import re
import ipaddress

logger = logging.getLogger(__name__)

class IOCManager:
    """
    Manages IOC (Indicators of Compromise) feeds and blocking decisions.
    Features:
    - Multiple threat intelligence sources
    - Per-token override capabilities 
    - API for IOC management
    - Automatic feed updates
    - Performance-optimized lookups
    """
    
    def __init__(self, db_url: str, update_interval_hours: int = 6):
        self.db_url = db_url
        self.update_interval_hours = update_interval_hours
        self.blocked_domains = set()
        self.blocked_ips = set()
        self.allow_overrides = {}  # token -> set of allowed domains/IPs
        self.block_overrides = {}  # token -> set of additionally blocked domains/IPs
        self._init_database()
        
    def _init_database(self):
        """Initialize IOC database schema"""
        db = DAL(self.db_url)
        
        # IOC feed sources
        db.define_table('ioc_feeds',
            Field('name', 'string', unique=True),
            Field('url', 'string'),
            Field('feed_type', 'string'),  # domain, ip, mixed
            Field('format', 'string'),  # txt, csv, json
            Field('enabled', 'boolean', default=True),
            Field('update_frequency_hours', 'integer', default=6),
            Field('last_update', 'datetime'),
            Field('last_success', 'datetime'),
            Field('entry_count', 'integer', default=0),
            Field('created_at', 'datetime', default=datetime.now),
            migrate=True
        )
        
        # IOC entries from feeds
        db.define_table('ioc_entries',
            Field('feed_id', 'reference ioc_feeds'),
            Field('indicator', 'string'),  # Domain or IP
            Field('indicator_type', 'string'),  # domain, ip
            Field('threat_type', 'string'),  # malware, phishing, botnet, etc.
            Field('confidence', 'integer', default=50),  # 0-100
            Field('description', 'text'),
            Field('first_seen', 'datetime'),
            Field('last_seen', 'datetime'),
            Field('added_at', 'datetime', default=datetime.now),
            migrate=True
        )
        
        # User/token-specific overrides
        db.define_table('ioc_overrides',
            Field('token_id', 'reference tokens'),
            Field('indicator', 'string'),
            Field('indicator_type', 'string'),  # domain, ip
            Field('override_type', 'string'),  # allow, block
            Field('reason', 'text'),
            Field('created_by', 'string'),
            Field('created_at', 'datetime', default=datetime.now),
            Field('expires_at', 'datetime'),
            migrate=True
        )
        
        # IOC lookup statistics
        db.define_table('ioc_stats',
            Field('date', 'date'),
            Field('feed_id', 'reference ioc_feeds'),
            Field('lookups', 'integer', default=0),
            Field('blocks', 'integer', default=0),
            Field('overrides_applied', 'integer', default=0),
            migrate=True
        )
        
        # Initialize default feeds
        self._create_default_feeds(db)
        
        db.commit()
        db.close()
        
    def _create_default_feeds(self, db: DAL):
        """Create default threat intelligence feeds"""
        default_feeds = [
            {
                'name': 'abuse.ch URLhaus',
                'url': 'https://urlhaus.abuse.ch/downloads/hostfile/',
                'feed_type': 'domain',
                'format': 'txt',
                'update_frequency_hours': 1
            },
            {
                'name': 'abuse.ch Malware Domains',
                'url': 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt',
                'feed_type': 'domain', 
                'format': 'txt',
                'update_frequency_hours': 6
            },
            {
                'name': 'Spamhaus DBL',
                'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                'feed_type': 'domain',
                'format': 'txt',
                'update_frequency_hours': 24
            },
            {
                'name': 'Emerging Threats Compromised IPs',
                'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'feed_type': 'ip',
                'format': 'txt',
                'update_frequency_hours': 1
            },
            {
                'name': 'Feodo Tracker',
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                'feed_type': 'ip',
                'format': 'txt',
                'update_frequency_hours': 1
            }
        ]
        
        for feed in default_feeds:
            existing = db(db.ioc_feeds.name == feed['name']).select().first()
            if not existing:
                db.ioc_feeds.insert(**feed)
                
    async def update_all_feeds(self):
        """Update all enabled IOC feeds"""
        db = DAL(self.db_url)
        
        try:
            feeds = db(db.ioc_feeds.enabled == True).select()
            
            for feed in feeds:
                try:
                    # Check if update is needed
                    if feed.last_update:
                        next_update = feed.last_update + timedelta(hours=feed.update_frequency_hours)
                        if datetime.now() < next_update:
                            continue
                            
                    logger.info(f"Updating IOC feed: {feed.name}")
                    await self._update_feed(db, feed)
                    
                except Exception as e:
                    logger.error(f"Failed to update feed {feed.name}: {e}")
                    
            # Rebuild in-memory caches
            await self._rebuild_caches(db)
            
        except Exception as e:
            logger.error(f"IOC feed update failed: {e}")
        finally:
            db.close()
            
    async def _update_feed(self, db: DAL, feed):
        """Update a single IOC feed"""
        try:
            # Download feed data
            async with aiohttp.ClientSession() as session:
                async with session.get(feed.url, timeout=30) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Parse feed content
                        indicators = await self._parse_feed_content(content, feed.format, feed.feed_type)
                        
                        # Clear old entries for this feed
                        db(db.ioc_entries.feed_id == feed.id).delete()
                        
                        # Insert new entries
                        entry_count = 0
                        for indicator in indicators:
                            db.ioc_entries.insert(
                                feed_id=feed.id,
                                indicator=indicator['value'],
                                indicator_type=indicator['type'],
                                threat_type=indicator.get('threat_type', 'unknown'),
                                confidence=indicator.get('confidence', 50),
                                description=indicator.get('description', ''),
                                first_seen=datetime.now(),
                                last_seen=datetime.now()
                            )
                            entry_count += 1
                            
                        # Update feed metadata
                        feed.update_record(
                            last_update=datetime.now(),
                            last_success=datetime.now(),
                            entry_count=entry_count
                        )
                        
                        logger.info(f"Updated feed {feed.name}: {entry_count} indicators")
                        
                    else:
                        logger.error(f"Feed {feed.name} returned HTTP {response.status}")
                        
        except Exception as e:
            logger.error(f"Failed to update feed {feed.name}: {e}")
            # Update last_update to prevent constant retries
            feed.update_record(last_update=datetime.now())
            
    async def _parse_feed_content(self, content: str, format_type: str, feed_type: str) -> List[Dict]:
        """Parse feed content based on format"""
        indicators = []
        
        try:
            if format_type == 'txt':
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue
                        
                    # Handle different text formats
                    if feed_type == 'domain':
                        # Extract domain from various formats
                        domain = self._extract_domain_from_line(line)
                        if domain:
                            indicators.append({
                                'value': domain,
                                'type': 'domain',
                                'threat_type': 'malware'
                            })
                            
                    elif feed_type == 'ip':
                        # Extract IP from various formats
                        ip = self._extract_ip_from_line(line)
                        if ip:
                            indicators.append({
                                'value': ip,
                                'type': 'ip',
                                'threat_type': 'malware'
                            })
                            
            elif format_type == 'json':
                data = json.loads(content)
                # Handle JSON format (structure depends on feed)
                # This would need customization per feed
                
        except Exception as e:
            logger.error(f"Failed to parse feed content: {e}")
            
        return indicators
        
    def _extract_domain_from_line(self, line: str) -> Optional[str]:
        """Extract domain from a text line"""
        # Remove common prefixes
        line = re.sub(r'^(0\.0\.0\.0\s+|127\.0\.0\.1\s+|::1\s+)', '', line)
        line = re.sub(r'^(www\.)', '', line)
        
        # Extract domain pattern
        domain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        match = re.search(domain_pattern, line)
        
        if match:
            domain = match.group(0).lower()
            # Validate domain
            if self._is_valid_domain(domain):
                return domain
                
        return None
        
    def _extract_ip_from_line(self, line: str) -> Optional[str]:
        """Extract IP address from a text line"""
        # IPv4 pattern
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ipv4_pattern, line)
        
        if match:
            ip = match.group(0)
            try:
                # Validate IP
                ipaddress.IPv4Address(ip)
                # Skip private/local IPs
                if not ipaddress.IPv4Address(ip).is_private and not ipaddress.IPv4Address(ip).is_loopback:
                    return ip
            except:
                pass
                
        return None
        
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        if len(domain) > 255 or len(domain) < 4:
            return False
            
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False
            
        # Must have at least one dot
        if '.' not in domain:
            return False
            
        # Check each part
        parts = domain.split('.')
        for part in parts:
            if len(part) == 0 or len(part) > 63:
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
                
        return True
        
    async def _rebuild_caches(self, db: DAL):
        """Rebuild in-memory caches for fast lookups"""
        try:
            # Clear existing caches
            self.blocked_domains.clear()
            self.blocked_ips.clear()
            
            # Load domains
            domain_entries = db(
                (db.ioc_entries.indicator_type == 'domain') &
                (db.ioc_feeds.id == db.ioc_entries.feed_id) &
                (db.ioc_feeds.enabled == True)
            ).select(db.ioc_entries.indicator)
            
            for entry in domain_entries:
                self.blocked_domains.add(entry.indicator.lower())
                
            # Load IPs
            ip_entries = db(
                (db.ioc_entries.indicator_type == 'ip') &
                (db.ioc_feeds.id == db.ioc_entries.feed_id) &
                (db.ioc_feeds.enabled == True)
            ).select(db.ioc_entries.indicator)
            
            for entry in ip_entries:
                self.blocked_ips.add(entry.indicator)
                
            # Load overrides
            await self._load_overrides(db)
            
            logger.info(f"IOC cache rebuilt: {len(self.blocked_domains)} domains, {len(self.blocked_ips)} IPs")
            
        except Exception as e:
            logger.error(f"Failed to rebuild IOC caches: {e}")
            
    async def _load_overrides(self, db: DAL):
        """Load token-specific overrides"""
        try:
            self.allow_overrides.clear()
            self.block_overrides.clear()
            
            # Get current overrides (not expired)
            overrides = db(
                (db.ioc_overrides.expires_at == None) |
                (db.ioc_overrides.expires_at > datetime.now())
            ).select()
            
            for override in overrides:
                token_id = override.token_id
                indicator = override.indicator.lower() if override.indicator_type == 'domain' else override.indicator
                
                if override.override_type == 'allow':
                    if token_id not in self.allow_overrides:
                        self.allow_overrides[token_id] = set()
                    self.allow_overrides[token_id].add(indicator)
                    
                elif override.override_type == 'block':
                    if token_id not in self.block_overrides:
                        self.block_overrides[token_id] = set()
                    self.block_overrides[token_id].add(indicator)
                    
        except Exception as e:
            logger.error(f"Failed to load IOC overrides: {e}")
            
    async def check_domain(self, domain: str, token_id: int = None) -> Tuple[bool, str]:
        """
        Check if domain should be blocked based on IOC feeds and overrides.
        Returns (should_block, reason)
        """
        domain_lower = domain.lower()
        
        # Check token-specific allow overrides first
        if token_id and token_id in self.allow_overrides:
            if domain_lower in self.allow_overrides[token_id]:
                return False, "Allowed by token override"
                
        # Check token-specific block overrides
        if token_id and token_id in self.block_overrides:
            if domain_lower in self.block_overrides[token_id]:
                return True, "Blocked by token override"
                
        # Check global IOC feeds
        if domain_lower in self.blocked_domains:
            return True, "Blocked by threat intelligence"
            
        # Check subdomains
        domain_parts = domain_lower.split('.')
        for i in range(1, len(domain_parts)):
            parent_domain = '.'.join(domain_parts[i:])
            if parent_domain in self.blocked_domains:
                return True, f"Blocked by parent domain: {parent_domain}"
                
        return False, "Not blocked"
        
    async def check_ip(self, ip_addr: str, token_id: int = None) -> Tuple[bool, str]:
        """
        Check if IP should be blocked based on IOC feeds and overrides.
        Returns (should_block, reason)
        """
        # Check token-specific allow overrides first
        if token_id and token_id in self.allow_overrides:
            if ip_addr in self.allow_overrides[token_id]:
                return False, "Allowed by token override"
                
        # Check token-specific block overrides
        if token_id and token_id in self.block_overrides:
            if ip_addr in self.block_overrides[token_id]:
                return True, "Blocked by token override"
                
        # Check global IOC feeds
        if ip_addr in self.blocked_ips:
            return True, "Blocked by threat intelligence"
            
        return False, "Not blocked"
        
    async def add_override(self, token_id: int, indicator: str, indicator_type: str,
                          override_type: str, reason: str = "", created_by: str = "",
                          expires_at: datetime = None) -> bool:
        """Add an IOC override for a specific token"""
        db = DAL(self.db_url)
        
        try:
            # Validate inputs
            if indicator_type not in ['domain', 'ip']:
                return False
            if override_type not in ['allow', 'block']:
                return False
                
            # Check if override already exists
            existing = db(
                (db.ioc_overrides.token_id == token_id) &
                (db.ioc_overrides.indicator == indicator) &
                (db.ioc_overrides.indicator_type == indicator_type)
            ).select().first()
            
            if existing:
                # Update existing override
                existing.update_record(
                    override_type=override_type,
                    reason=reason,
                    created_by=created_by,
                    created_at=datetime.now(),
                    expires_at=expires_at
                )
            else:
                # Create new override
                db.ioc_overrides.insert(
                    token_id=token_id,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    override_type=override_type,
                    reason=reason,
                    created_by=created_by,
                    expires_at=expires_at
                )
                
            db.commit()
            
            # Reload overrides
            await self._load_overrides(db)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to add IOC override: {e}")
            return False
        finally:
            db.close()
            
    async def remove_override(self, token_id: int, indicator: str, indicator_type: str) -> bool:
        """Remove an IOC override for a specific token"""
        db = DAL(self.db_url)
        
        try:
            deleted = db(
                (db.ioc_overrides.token_id == token_id) &
                (db.ioc_overrides.indicator == indicator) &
                (db.ioc_overrides.indicator_type == indicator_type)
            ).delete()
            
            db.commit()
            
            if deleted > 0:
                # Reload overrides
                await self._load_overrides(db)
                return True
                
        except Exception as e:
            logger.error(f"Failed to remove IOC override: {e}")
        finally:
            db.close()
            
        return False
        
    async def get_overrides(self, token_id: int = None) -> List[Dict]:
        """Get IOC overrides, optionally filtered by token"""
        db = DAL(self.db_url)
        
        try:
            if token_id:
                overrides = db(db.ioc_overrides.token_id == token_id).select()
            else:
                overrides = db(db.ioc_overrides).select()
                
            result = []
            for override in overrides:
                result.append({
                    'token_id': override.token_id,
                    'indicator': override.indicator,
                    'indicator_type': override.indicator_type,
                    'override_type': override.override_type,
                    'reason': override.reason,
                    'created_by': override.created_by,
                    'created_at': override.created_at.isoformat() if override.created_at else None,
                    'expires_at': override.expires_at.isoformat() if override.expires_at else None
                })
                
            return result
            
        except Exception as e:
            logger.error(f"Failed to get IOC overrides: {e}")
            return []
        finally:
            db.close()
            
    async def get_stats(self) -> Dict:
        """Get IOC service statistics"""
        db = DAL(self.db_url)
        
        try:
            # Feed statistics
            feeds = db(db.ioc_feeds).select()
            feed_stats = []
            
            total_indicators = 0
            for feed in feeds:
                feed_indicators = db(db.ioc_entries.feed_id == feed.id).count()
                total_indicators += feed_indicators
                
                feed_stats.append({
                    'name': feed.name,
                    'enabled': feed.enabled,
                    'indicators': feed_indicators,
                    'last_update': feed.last_update.isoformat() if feed.last_update else None,
                    'last_success': feed.last_success.isoformat() if feed.last_success else None
                })
                
            # Override statistics
            total_overrides = db(db.ioc_overrides).count()
            allow_overrides = db(db.ioc_overrides.override_type == 'allow').count()
            block_overrides = db(db.ioc_overrides.override_type == 'block').count()
            
            return {
                'feeds': {
                    'total_feeds': len(feeds),
                    'enabled_feeds': len([f for f in feeds if f.enabled]),
                    'total_indicators': total_indicators,
                    'cached_domains': len(self.blocked_domains),
                    'cached_ips': len(self.blocked_ips),
                    'feed_details': feed_stats
                },
                'overrides': {
                    'total_overrides': total_overrides,
                    'allow_overrides': allow_overrides,
                    'block_overrides': block_overrides
                },
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get IOC stats: {e}")
            return {}
        finally:
            db.close()
            
    async def cleanup_expired_overrides(self):
        """Remove expired IOC overrides"""
        db = DAL(self.db_url)
        
        try:
            deleted = db(
                (db.ioc_overrides.expires_at != None) &
                (db.ioc_overrides.expires_at <= datetime.now())
            ).delete()
            
            db.commit()
            
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} expired IOC overrides")
                await self._load_overrides(db)
                
            return deleted
            
        except Exception as e:
            logger.error(f"IOC override cleanup failed: {e}")
            return 0
        finally:
            db.close()