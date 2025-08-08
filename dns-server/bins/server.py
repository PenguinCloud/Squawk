#!/usr/bin/env python3
import socketserver
import requests
import http.server
import dns.resolver
import json
import sys
import os
import getopt
import ssl
from pydal import DAL, Field
from pydal.validators import IS_NOT_EMPTY, IS_IN_SET, IS_MATCH
from datetime import datetime

PORT = 8080
GOOGLE_DOH_URL = "https://dns.google/dns-query"
AUTH_TOKEN = None
KEY_FILE = None
CERT_FILE = None
DB_TYPE = None
DB_URL = None
ALLOWED_DOMAINS = []
USE_NEW_AUTH = False  # Flag to use new token management system

class DNSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global AUTH_TOKEN, ALLOWED_DOMAINS, DB_TYPE, DB_URL, USE_NEW_AUTH
        
        # Extract token from Authorization header
        token = self.headers.get('Authorization')
        token = token.split('Bearer ')[-1] if token else None
        
        # Parse query parameters
        query = self.path.split('?name=')[-1]
        name = query.split('&')[0]
        dnsType = query.split('&type=')[-1] if '&type=' in query else 'A'
        
        if name:
            # Validate domain format
            if not self.is_valid_domain(name):
                print(f"Invalid domain: {name}")
                self.send_response(400)
                self.end_headers()
                return
            
            # Check authorization
            if USE_NEW_AUTH and DB_TYPE and DB_URL:
                # Use new token management system
                if not self.check_token_permission_new(token, name):
                    print(f"Access denied for token to domain: {name}")
                    self.send_response(403)
                    self.end_headers()
                    self.log_query_new(token, name, dnsType, 'denied')
                    return
                self.log_query_new(token, name, dnsType, 'allowed')
            elif AUTH_TOKEN:
                # Use legacy single-token system
                if token != AUTH_TOKEN:
                    print(f"Invalid token: {token}")
                    self.send_response(403)
                    self.end_headers()
                    return
                
                if ALLOWED_DOMAINS and not any(name.endswith(domain) for domain in ALLOWED_DOMAINS):
                    print(f"Domain not in allowed list: {name}")
                    self.send_response(403)
                    self.end_headers()
                    return
            
            # Resolve DNS
            print(f"Resolving {name} with type {dnsType}")
            response = self.resolve_dns(name, dnsType)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(response.encode())
        else:
            self.send_response(400)
            self.end_headers()

    def resolve_dns(self, query, record_type='A'):
        resolver = dns.resolver.Resolver()
        try:
            # Map common record types
            if record_type.upper() in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR']:
                answer = resolver.resolve(query, record_type.upper())
            else:
                answer = resolver.resolve(query)
            
            result = {
                "Status": 0,
                "Answer": [{"name": query, "type": record_type, "data": rdata.to_text()} for rdata in answer]
            }
        except Exception as e:
            result = {
                "Status": 2,
                "Comment": str(e)
            }
        return json.dumps(result)

    def is_valid_domain(self, domain):
        import re
        pattern = re.compile(
            r'^(?:[a-zA-Z0-9]'  # First character of the domain
            r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'  # Sub domain + hostname
            r'+[a-zA-Z]{2,6}\.?$'  # First level TLD
        )
        return pattern.match(domain) is not None
    
    def check_token_permission_new(self, token_value, domain_name):
        """Check permission using new token management system"""
        if not token_value:
            return False
        
        # Connect to the same database as the web console
        db_path = os.path.join(os.path.dirname(__file__), '..', 'web', 'apps', 'dns_console', 'databases', 'dns_auth.db')
        db = DAL(f'sqlite://{db_path}', folder=os.path.dirname(db_path))
        
        # Define tables (must match console schema)
        db.define_table('tokens',
            Field('token', 'string'),
            Field('name', 'string'),
            Field('active', 'boolean'),
            Field('last_used', 'datetime'),
            migrate=False
        )
        
        db.define_table('domains',
            Field('name', 'string'),
            migrate=False
        )
        
        db.define_table('token_domains',
            Field('token_id', 'reference tokens'),
            Field('domain_id', 'reference domains'),
            migrate=False
        )
        
        # Check if token exists and is active
        token_record = db(db.tokens.token == token_value).select().first()
        if not token_record or not token_record.active:
            db.close()
            return False
        
        # Check for wildcard domain permission
        wildcard = db((db.token_domains.token_id == token_record.id) & 
                     (db.domains.id == db.token_domains.domain_id) &
                     (db.domains.name == '*')).select().first()
        if wildcard:
            # Update last_used timestamp
            token_record.update_record(last_used=datetime.now())
            db.commit()
            db.close()
            return True
        
        # Check for specific domain or parent domain permission
        parts = domain_name.split('.')
        for i in range(len(parts)):
            check_domain = '.'.join(parts[i:])
            permission = db((db.token_domains.token_id == token_record.id) & 
                          (db.domains.id == db.token_domains.domain_id) &
                          (db.domains.name == check_domain)).select().first()
            if permission:
                # Update last_used timestamp
                token_record.update_record(last_used=datetime.now())
                db.commit()
                db.close()
                return True
        
        db.close()
        return False
    
    def log_query_new(self, token_value, domain, query_type, status):
        """Log query using new system"""
        try:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'web', 'apps', 'dns_console', 'databases', 'dns_auth.db')
            db = DAL(f'sqlite://{db_path}', folder=os.path.dirname(db_path))
            
            db.define_table('tokens',
                Field('token', 'string'),
                migrate=False
            )
            
            db.define_table('query_logs',
                Field('token_id', 'reference tokens'),
                Field('domain_queried', 'string'),
                Field('query_type', 'string'),
                Field('status', 'string'),
                Field('client_ip', 'string'),
                Field('timestamp', 'datetime'),
                migrate=False
            )
            
            token_record = db(db.tokens.token == token_value).select().first() if token_value else None
            
            db.query_logs.insert(
                token_id=token_record.id if token_record else None,
                domain_queried=domain,
                query_type=query_type,
                status=status,
                client_ip=self.client_address[0] if self.client_address else None,
                timestamp=datetime.now()
            )
            db.commit()
            db.close()
        except Exception as e:
            print(f"Error logging query: {e}")

def get_token_from_db(db_type, db_url, domain="*"):
    """Legacy function for single-token system"""
    db = DAL(f"{db_type}://{db_url}")
    db.define_table('auth', 
                    Field('token', requires=IS_NOT_EMPTY()), 
                    Field('domain', requires=[IS_NOT_EMPTY(), IS_MATCH(r'^[a-zA-Z0-9.-]+$')]))
    row = db((db.auth.domain == domain) | (db.auth.domain == "*")).select().first()
    db.close()
    return (row.token, row.domain.split(',')) if row else (None, [])

def main(argv):
    global AUTH_TOKEN, PORT, KEY_FILE, CERT_FILE, DB_TYPE, DB_URL, ALLOWED_DOMAINS, USE_NEW_AUTH
    
    try:
        opts, args = getopt.getopt(argv, "a:p:k:c:d:u:n", ["auth=", "port=", "key=", "cert=", "dbtype=", "dburl=", "new-auth"])
    except getopt.GetoptError:
        print('server.py -a <authtoken> -p <port> -k <keyfile> -c <certfile> -d <dbtype> -u <dburl> [-n|--new-auth]')
        print('  -n, --new-auth : Use new token management system with web console')
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ("-a", "--auth"):
            AUTH_TOKEN = arg
        elif opt in ("-p", "--port"):
            PORT = int(arg)
        elif opt in ("-k", "--key"):
            KEY_FILE = arg
        elif opt in ("-c", "--cert"):
            CERT_FILE = arg
        elif opt in ("-d", "--dbtype"):
            DB_TYPE = arg
        elif opt in ("-u", "--dburl"):
            DB_URL = arg
        elif opt in ("-n", "--new-auth"):
            USE_NEW_AUTH = True
    
    # If using new auth system, ensure database exists
    if USE_NEW_AUTH:
        print("Using new token management system with web console")
        # Set default database if not specified
        if not DB_TYPE:
            DB_TYPE = 'sqlite'
        if not DB_URL:
            DB_URL = 'dns_auth.db'
    elif DB_TYPE and DB_URL and not USE_NEW_AUTH:
        # Legacy mode
        AUTH_TOKEN, ALLOWED_DOMAINS = get_token_from_db(DB_TYPE, DB_URL)

if __name__ == "__main__":
    main(sys.argv[1:])
    httpd = socketserver.TCPServer(("", PORT), DNSHandler)
    if KEY_FILE and CERT_FILE:
        httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=KEY_FILE, certfile=CERT_FILE, server_side=True)
        print(f"Serving DNS-over-HTTPS on port {PORT} with TLS")
    else:
        print(f"Serving DNS-over-HTTPS on port {PORT}")
    
    if USE_NEW_AUTH:
        print(f"Web console available at: http://localhost:{PORT}/dns_console")
    
    httpd.serve_forever()