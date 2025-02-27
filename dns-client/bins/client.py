#!/usr/bin/env python3

import requests
import json
import sys
import getopt
import socket
import threading
import logging
import yaml

class DNSOverHTTPSClient:
    def __init__(self, dns_server_url="https://dns.google/dns-query", auth_token=None):
        self.dns_server_url = dns_server_url
        self.auth_token = auth_token

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
            response = requests.get(self.dns_server_url, headers=headers, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.debug(f"Error: {e}")
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

    try:
        opts, args = getopt.getopt(argv, "hd:t:s:a:c:uT", ["domain=", "type=", "server=", "auth=", "config=", "udp", "tcp"])
    except getopt.GetoptError:
        logging.debug('client.py -d <domain> -t <record_type> -s <dns_server_url> -a <auth_token> -c <config_file> [-u] [-T]')
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

    if config_file:
        config = load_config(config_file)
        domain = config.get('domain', domain)
        record_type = config.get('type', record_type)
        dns_server_url = config.get('server', dns_server_url)
        auth_token = config.get('auth', auth_token)

    if not domain:
        logging.debug('Domain is required. Use -d <domain> to specify the domain.')
        sys.exit(2)

    client = DNSOverHTTPSClient(dns_server_url, auth_token)
    result = client.query(domain, record_type)
    logging.debug(json.dumps(result, indent=4))

    forwarder = DNSForwarder(client, listen_udp=listen_udp, listen_tcp=listen_tcp)
    forwarder.start()

if __name__ == "__main__":
    main(sys.argv[1:])
