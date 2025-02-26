import socketserver
import requests
import http.server
import dns.resolver
import json
import sys
import getopt
import ssl
from pydal import DAL, Field
from pydal.validators import IS_NOT_EMPTY, IS_IN_SET, IS_MATCH

PORT = 8080
GOOGLE_DOH_URL = "https://dns.google/dns-query"
AUTH_TOKEN = None
KEY_FILE = None
CERT_FILE = None
DB_TYPE = None
DB_URL = None
ALLOWED_DOMAINS = []

class DNSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global AUTH_TOKEN, ALLOWED_DOMAINS
        token = self.headers.get('Authorization')
        if AUTH_TOKEN and token != AUTH_TOKEN:
            self.send_response(403)
            self.end_headers()
            return

        query = self.path.split('?name=')[-1]
        if query:
            if not self.is_valid_domain(query):
                self.send_response(400)
                self.end_headers()
                return

            if AUTH_TOKEN and not any(query.endswith(domain) for domain in ALLOWED_DOMAINS):
                self.send_response(403)
                self.end_headers()
                return

            response = self.resolve_dns(query)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(response.encode())
        else:
            self.send_response(400)
            self.end_headers()

    def resolve_dns(self, query):
        resolver = dns.resolver.Resolver()
        try:
            answer = resolver.resolve(query)
            result = {
                "Status": 0,
                "Answer": [{"name": query, "data": rdata.to_text()} for rdata in answer]
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

def get_token_from_db(db_type, db_url, domain="*"):
    db = DAL(f"{db_type}://{db_url}")
    db.define_table('auth', 
                    Field('token', requires=IS_NOT_EMPTY()), 
                    Field('domain', requires=[IS_NOT_EMPTY(), IS_MATCH(r'^[a-zA-Z0-9.-]+$')]))
    row = db((db.auth.domain == domain) | (db.auth.domain == "*")).select().first()
    db.close()
    return (row.token, row.domain.split(',')) if row else (None, [])

def main(argv):
    global AUTH_TOKEN, PORT, KEY_FILE, CERT_FILE, DB_TYPE, DB_URL, ALLOWED_DOMAINS
    try:
        opts, args = getopt.getopt(argv, "t:p:k:c:d:u:", ["token=", "port=", "key=", "cert=", "dbtype=", "dburl="])
    except getopt.GetoptError:
        print('server.py -t <token> -p <port> -k <keyfile> -c <certfile> -d <dbtype> -u <dburl>')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-t", "--token"):
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

    if DB_TYPE and DB_URL:
        AUTH_TOKEN, ALLOWED_DOMAINS = get_token_from_db(DB_TYPE, DB_URL)

if __name__ == "__main__":
    main(sys.argv[1:])
    httpd = socketserver.TCPServer(("", PORT), DNSHandler)
    if KEY_FILE and CERT_FILE:
        httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=KEY_FILE, certfile=CERT_FILE, server_side=True)
        print(f"Serving on port {PORT} with TLS")
    else:
        print(f"Serving on port {PORT}")
    httpd.serve_forever()