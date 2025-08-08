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

class DNSOverHTTPSClient:
    def __init__(self, dns_server_url="https://dns.google/dns-query", auth_token=None, 
                 client_cert=None, client_key=None, ca_cert=None, verify_ssl=True):
        self.dns_server_url = dns_server_url
        self.auth_token = auth_token
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_cert = ca_cert
        self.verify_ssl = verify_ssl
        
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

    def query(self, domain, record_type="A"):
        params = {
            "name": domain,
            "type": record_type
        }
        headers = {
            "Accept": "application/dns-json"
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        try:
            response = self.session.get(self.dns_server_url, headers=headers, params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except requests.exceptions.SSLError as e:
            logging.error(f"SSL Error (check certificates): {e}")
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            logging.debug(f"Request Error: {e}")
            sys.exit(1)

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
