#!/usr/bin/env python3

import requests
import json
import sys
import getopt
import socket
import threading
import logging
import yaml
import os
import ssl
import ipaddress
import re
from urllib.parse import urlparse

class DNSOverHTTPSClient:
    # DNS label validation regex (RFC 1035)
    DNS_LABEL_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')
    
    # Valid DNS record types
    VALID_RECORD_TYPES = {
        'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 
        'SRV', 'CAA', 'DNSKEY', 'DS', 'NAPTR', 'SSHFP', 'TLSA', 'ANY'
    }
    
    @staticmethod
    def validate_dns_name(domain):
        """Validate a DNS domain name according to RFC 1035"""
        if not domain:
            raise ValueError("DNS name cannot be empty")
        
        # Check overall length (max 253 characters)
        if len(domain) > 253:
            raise ValueError(f"DNS name too long: {len(domain)} characters (max 253)")
        
        # Remove trailing dot if present
        domain = domain.rstrip('.')
        
        # Check for invalid characters
        invalid_chars = set(' !@#$%^&*()+={}[]|\\:;"\'<>,?/`~')
        if any(c in invalid_chars for c in domain):
            raise ValueError("DNS name contains invalid characters")
        
        # Split into labels and validate each
        labels = domain.split('.')
        if not labels:
            raise ValueError("DNS name has no labels")
        
        for i, label in enumerate(labels):
            # Check label length (max 63 characters)
            if not label:
                raise ValueError(f"DNS name contains empty label at position {i}")
            if len(label) > 63:
                raise ValueError(f"DNS label '{label}' too long: {len(label)} characters (max 63)")
            
            # Special case: .arpa domains for reverse DNS
            if i == len(labels) - 1 and label == 'arpa':
                continue
            
            # Check label format
            if not DNSOverHTTPSClient.DNS_LABEL_REGEX.match(label):
                # Special case for IDN/punycode domains
                if label.startswith('xn--'):
                    continue
                raise ValueError(f"Invalid DNS label '{label}': must start/end with alphanumeric "
                               f"and contain only letters, digits, and hyphens")
            
            # Check for consecutive hyphens (except in punycode)
            if '--' in label and not label.startswith('xn--'):
                raise ValueError(f"Invalid DNS label '{label}': contains consecutive hyphens")
        
        return True
    
    @staticmethod
    def validate_record_type(record_type):
        """Validate DNS record type"""
        record_type = record_type.upper()
        if record_type not in DNSOverHTTPSClient.VALID_RECORD_TYPES:
            raise ValueError(f"Invalid DNS record type '{record_type}': must be one of "
                           f"{', '.join(sorted(DNSOverHTTPSClient.VALID_RECORD_TYPES))}")
        return record_type
    @staticmethod
    def _validate_server_url(dns_server_url):
        """Validate that the server URL uses an IP address to prevent DNS loops"""
        if not dns_server_url:
            raise ValueError("DNS server URL cannot be empty")
        
        try:
            parsed_url = urlparse(dns_server_url)
        except Exception as e:
            raise ValueError(f"Invalid DNS server URL format: {e}")
        
        if parsed_url.scheme not in ['http', 'https']:
            raise ValueError(f"DNS server URL must use http or https scheme, got: {parsed_url.scheme}")
        
        if not parsed_url.hostname:
            raise ValueError("DNS server URL must include a hostname")
        
        host = parsed_url.hostname.lower()
        
        # Try to parse as IP address
        try:
            ipaddress.ip_address(host)
            return  # Valid IP address
        except ValueError:
            pass  # Not an IP address, continue with hostname checks
        
        # Special case: allow localhost for development
        if host == "localhost":
            return
        
        # Special case: allow well-known public DNS providers
        allowed_hosts = [
            "dns.google",
            "dns.google.com",  # Legacy Google DNS domain
            "cloudflare-dns.com",
            "1.1.1.1",  # Cloudflare primary
            "1.0.0.1",  # Cloudflare secondary
            "dns.quad9.net",
            "dns.opendns.com",
            "doh.opendns.com",
            "dns.nextdns.io",
            "doh.cleanbrowsing.org",
        ]
        
        # Check if host matches or is subdomain of allowed hosts
        for allowed in allowed_hosts:
            if host == allowed or host.startswith(allowed + "."):
                # Don't show warning for major public DNS providers
                if "google" not in host and "cloudflare" not in host and host not in ["1.1.1.1", "1.0.0.1"]:
                    print(f"INFO: Using public DNS provider '{host}'")
                return
        
        raise ValueError(f"DNS server URL must use an IP address (not hostname '{host}') to prevent DNS resolution loops. Use the IP address of your DNS server instead")

    @staticmethod
    def _normalize_server_url(server_url):
        """Normalize URLs for known public DNS providers"""
        parsed_url = urlparse(server_url)
        host = parsed_url.hostname.lower() if parsed_url.hostname else ""
        
        # Google DNS - ensure correct path
        if "dns.google" in host:
            if not parsed_url.path or parsed_url.path == "/":
                parsed_url = parsed_url._replace(path="/resolve")
                
        # Cloudflare DNS - ensure correct path  
        elif "cloudflare" in host or host in ["1.1.1.1", "1.0.0.1"]:
            if not parsed_url.path or parsed_url.path == "/":
                parsed_url = parsed_url._replace(path="/dns-query")
                
        # Quad9 DNS
        elif "dns.quad9.net" in host:
            if not parsed_url.path or parsed_url.path == "/":
                parsed_url = parsed_url._replace(path="/dns-query")
                
        return parsed_url.geturl()

    def __init__(self, dns_server_url="https://dns.google/dns-query", auth_token=None, 
                 client_cert=None, client_key=None, ca_cert=None, verify_ssl=True,
                 dns_server_urls=None, max_retries=None, retry_delay=2):
        # Handle multiple server URLs
        if dns_server_urls and isinstance(dns_server_urls, list):
            self.dns_server_urls = dns_server_urls
        elif dns_server_url:
            self.dns_server_urls = [dns_server_url]
        else:
            raise ValueError("Must provide either dns_server_url or dns_server_urls")
        
        # Validate and normalize all server URLs
        normalized_urls = []
        for i, url in enumerate(self.dns_server_urls):
            try:
                self._validate_server_url(url)
                normalized_urls.append(self._normalize_server_url(url))
            except ValueError as e:
                raise ValueError(f"Invalid server URL at index {i}: {e}")
        self.dns_server_urls = normalized_urls
        
        # Legacy support
        self.dns_server_url = self.dns_server_urls[0]
        
        self.auth_token = auth_token
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_cert = ca_cert
        self.verify_ssl = verify_ssl
        
        # Failover configuration
        self.max_retries = max_retries if max_retries is not None else len(self.dns_server_urls) * 2
        self.retry_delay = retry_delay
        self.current_server_index = 0
        
        # Create requests session with mTLS support
        self.session = requests.Session()
        self._configure_ssl()
    
    def _configure_ssl(self):
        """Configure SSL settings for the session"""
        # Configure certificate verification
        if self.ca_cert and os.path.exists(self.ca_cert):
            self.session.verify = self.ca_cert
        elif not self.verify_ssl:
            self.session.verify = False
            # Suppress SSL warnings if verification is disabled
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Configure client certificate for mTLS
        if self.client_cert and self.client_key:
            if os.path.exists(self.client_cert) and os.path.exists(self.client_key):
                self.session.cert = (self.client_cert, self.client_key)
                logging.info(f"mTLS enabled with client certificate: {self.client_cert}")
            else:
                logging.warning("Client certificate or key file not found, mTLS disabled")
        elif self.client_cert and os.path.exists(self.client_cert):
            # Single file containing both cert and key
            self.session.cert = self.client_cert
            logging.info(f"mTLS enabled with combined certificate file: {self.client_cert}")

    def _next_server(self):
        """Advance to the next server in the list (round-robin)"""
        self.current_server_index = (self.current_server_index + 1) % len(self.dns_server_urls)
    
    def query(self, domain, record_type="A"):
        """Query DNS using failover logic across multiple servers"""
        # Validate domain name
        try:
            self.validate_dns_name(domain)
        except ValueError as e:
            logging.error(f"Invalid domain name: {e}")
            raise
        
        # Validate and normalize record type
        try:
            record_type = self.validate_record_type(record_type)
        except ValueError as e:
            logging.error(f"Invalid record type: {e}")
            raise
        
        params = {
            "name": domain,
            "type": record_type
        }
        headers = {
            "Accept": "application/dns-json"
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        
        last_error = None
        errors = []
        
        # Try each server with retry logic
        for attempt in range(self.max_retries):
            current_server = self.dns_server_urls[self.current_server_index]
            
            try:
                response = self.session.get(current_server, headers=headers, params=params, timeout=30)
                if response.status_code == 200:
                    return response.json()
                else:
                    error_msg = f"HTTP {response.status_code} from {current_server}: {response.text}"
                    last_error = error_msg
                    errors.append(error_msg)
                    logging.warning(error_msg)
                    
            except requests.exceptions.SSLError as e:
                error_msg = f"SSL Error for {current_server}: {e}"
                last_error = error_msg
                errors.append(error_msg)
                logging.warning(error_msg)
                
            except requests.exceptions.RequestException as e:
                error_msg = f"Request Error for {current_server}: {e}"
                last_error = error_msg
                errors.append(error_msg)
                logging.warning(error_msg)
            
            # Move to next server
            self._next_server()
            
            # Add delay between retries (except for the last attempt)
            if attempt < self.max_retries - 1:
                import time
                time.sleep(self.retry_delay)
        
        # All servers failed
        error_summary = f"All {len(self.dns_server_urls)} DNS servers failed after {self.max_retries} attempts"
        if len(errors) > 1:
            error_summary += f": {'; '.join(errors)}"
        else:
            error_summary += f": {last_error}" if last_error else ""
            
        logging.error(error_summary)
        raise Exception(error_summary)

class DNSForwarder:
    def __init__(self, dns_client, udp_port=53, tcp_port=53, listen_udp=False, listen_tcp=False):
        self.dns_client = dns_client
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.listen_udp = listen_udp
        self.listen_tcp = listen_tcp

    def start(self):
        threads = []
        if self.listen_udp:
            udp_thread = threading.Thread(target=self.start_udp_server)
            threads.append(udp_thread)
        if self.listen_tcp:
            tcp_thread = threading.Thread(target=self.start_tcp_server)
            threads.append(tcp_thread)
        
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def start_udp_server(self):
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(("127.0.0.1", self.udp_port))
        logging.debug(f"UDP server listening on 127.0.0.1:{self.udp_port}")
        while True:
            data, addr = udp_sock.recvfrom(512)
            response = self.handle_request(data)
            udp_sock.sendto(response, addr)

    def start_tcp_server(self):
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.bind(("127.0.0.1", self.tcp_port))
        tcp_sock.listen(5)
        logging.debug(f"TCP server listening on 127.0.0.1:{self.tcp_port}")
        while True:
            conn, addr = tcp_sock.accept()
            data = conn.recv(512)
            response = self.handle_request(data)
            conn.sendall(response)
            conn.close()

    def handle_request(self, data):
        domain = "example.com"  # Extract the domain from the DNS request
        record_type = "A"  # Extract the record type from the DNS request
        result = self.dns_client.query(domain, record_type)
        response = b""  # Create a proper DNS response
        return response

def load_config(config_file):
    with open(config_file, 'r') as file:
        return yaml.safe_load(file)

def main(argv):
    logging.basicConfig(level=logging.DEBUG)
    
    domain = ''
    record_type = 'A'
    dns_server_url = "https://dns.google/resolve"
    auth_token = None
    config_file = None
    listen_udp = False
    listen_tcp = False
    client_cert = None
    client_key = None
    ca_cert = None
    verify_ssl = True

    try:
        opts, args = getopt.getopt(argv, "hd:t:s:a:c:uTk:C:K:v", 
                                  ["domain=", "type=", "server=", "auth=", "config=", 
                                   "udp", "tcp", "ca-cert=", "client-cert=", "client-key=", "verify"])
    except getopt.GetoptError:
        print('client.py -d <domain> -t <record_type> -s <dns_server_url> -a <auth_token> -c <config_file> [-u] [-T] [--ca-cert=<ca.crt>] [--client-cert=<client.crt>] [--client-key=<client.key>] [--verify]')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            logging.debug('client.py -d <domain> -t <record_type> -s <dns_server_url> -a <auth_token> -c <config_file> [-u] [-T]')
            sys.exit()
        elif opt in ("-d", "--domain"):
            domain = arg
        elif opt in ("-t", "--type"):
            record_type = arg
        elif opt in ("-s", "--server"):
            dns_server_url = arg
        elif opt in ("-a", "--auth"):
            auth_token = arg
        elif opt in ("-c", "--config"):
            config_file = arg
        elif opt in ("-u", "--udp"):
            listen_udp = True
        elif opt in ("-T", "--tcp"):
            listen_tcp = True
        elif opt in ("-k", "--ca-cert"):
            ca_cert = arg
        elif opt in ("-C", "--client-cert"):
            client_cert = arg
        elif opt in ("-K", "--client-key"):
            client_key = arg
        elif opt in ("-v", "--verify"):
            verify_ssl = True

    if config_file:
        config = load_config(config_file)
        domain = config.get('domain', domain)
        record_type = config.get('type', record_type)
        dns_server_url = config.get('server', dns_server_url)
        auth_token = config.get('auth', auth_token)
        client_cert = config.get('client_cert', client_cert)
        client_key = config.get('client_key', client_key)
        ca_cert = config.get('ca_cert', ca_cert)
        verify_ssl = config.get('verify_ssl', verify_ssl)

    # Check environment variables for all configuration options
    if not dns_server_url or dns_server_url == "https://dns.google/resolve":
        dns_server_url = os.getenv('SQUAWK_SERVER_URL', dns_server_url)
    if not auth_token:
        auth_token = os.getenv('SQUAWK_AUTH_TOKEN')
    if not client_cert:
        client_cert = os.getenv('SQUAWK_CLIENT_CERT', os.getenv('CLIENT_CERT_PATH'))
    if not client_key:
        client_key = os.getenv('SQUAWK_CLIENT_KEY', os.getenv('CLIENT_KEY_PATH'))  
    if not ca_cert:
        ca_cert = os.getenv('SQUAWK_CA_CERT', os.getenv('CA_CERT_PATH'))
    
    # Additional environment variables
    if not domain:
        domain = os.getenv('SQUAWK_DOMAIN')
    if record_type == 'A':
        record_type = os.getenv('SQUAWK_RECORD_TYPE', 'A')
    
    # Override verify_ssl from environment if not explicitly set
    verify_ssl_env = os.getenv('SQUAWK_VERIFY_SSL', '').lower()
    if verify_ssl_env in ['true', '1', 'yes']:
        verify_ssl = True
    elif verify_ssl_env in ['false', '0', 'no']:
        verify_ssl = False

    if not domain:
        logging.debug('Domain is required. Use -d <domain> to specify the domain.')
        sys.exit(2)

    client = DNSOverHTTPSClient(
        dns_server_url, 
        auth_token, 
        client_cert=client_cert,
        client_key=client_key,
        ca_cert=ca_cert,
        verify_ssl=verify_ssl
    )
    result = client.query(domain, record_type)
    logging.debug(json.dumps(result, indent=4))

    forwarder = DNSForwarder(client, listen_udp=listen_udp, listen_tcp=listen_tcp)
    forwarder.start()

if __name__ == "__main__":
    main(sys.argv[1:])
