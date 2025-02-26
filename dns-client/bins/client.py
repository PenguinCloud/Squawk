#!/usr/bin/env python3

import requests
import json
import sys
import getopt

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
            print(f"Error: {e}")
            sys.exit(1)
       

def main(argv):
    domain = ''
    record_type = 'A'
    dns_server_url = "https://dns.google/dns-query"
    auth_token = None
    try:
        opts, args = getopt.getopt(argv, "hd:t:s:a:", ["domain=", "type=", "server=", "auth="])
    except getopt.GetoptError:
        print('client.py -d <domain> -t <record_type> -s <dns_server_url> -a <auth_token>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('client.py -d <domain> -t <record_type> -s <dns_server_url> -a <auth_token>')
            sys.exit()
        elif opt in ("-d", "--domain"):
            domain = arg
        elif opt in ("-t", "--type"):
            record_type = arg
        elif opt in ("-s", "--server"):
            dns_server_url = arg
        elif opt in ("-a", "--auth"):
            auth_token = arg

    if not domain:
        print('Domain is required. Use -d <domain> to specify the domain.')
        sys.exit(2)

    client = DNSOverHTTPSClient(dns_server_url, auth_token)
    result = client.query(domain, record_type)
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main(sys.argv[1:])