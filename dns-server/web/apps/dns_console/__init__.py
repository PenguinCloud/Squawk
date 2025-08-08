"""
DNS Console - Token and Domain Management System for Squawk
"""

from py4web import action, request, response, abort, redirect, URL
from py4web.core import Fixture
from pydal import DAL, Field
from pydal.validators import IS_NOT_EMPTY, IS_NOT_IN_DB, IS_IN_DB, IS_MATCH
import os
import secrets
import json
from datetime import datetime

# Database configuration
db_folder = os.path.join(os.path.dirname(__file__), 'databases')
if not os.path.exists(db_folder):
    os.makedirs(db_folder)

db = DAL(f'sqlite://dns_auth.db', folder=db_folder, pool_size=1)

# Define database tables
db.define_table('tokens',
    Field('token', 'string', length=255, unique=True, notnull=True, 
          requires=[IS_NOT_EMPTY(), IS_NOT_IN_DB(db, 'tokens.token')]),
    Field('name', 'string', length=100, notnull=True, requires=IS_NOT_EMPTY()),
    Field('description', 'text'),
    Field('created_at', 'datetime', default=datetime.now, writable=False),
    Field('last_used', 'datetime'),
    Field('active', 'boolean', default=True),
    format='%(name)s'
)

db.define_table('domains',
    Field('name', 'string', length=255, unique=True, notnull=True,
          requires=[IS_NOT_EMPTY(), 
                   IS_NOT_IN_DB(db, 'domains.name'),
                   IS_MATCH(r'^(\*|[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)$',
                           error_message='Invalid domain format')]),
    Field('description', 'text'),
    Field('created_at', 'datetime', default=datetime.now, writable=False),
    format='%(name)s'
)

db.define_table('token_domains',
    Field('token_id', 'reference tokens', notnull=True, ondelete='CASCADE'),
    Field('domain_id', 'reference domains', notnull=True, ondelete='CASCADE'),
    Field('created_at', 'datetime', default=datetime.now, writable=False),
)

db.define_table('query_logs',
    Field('token_id', 'reference tokens', ondelete='SET NULL'),
    Field('domain_queried', 'string', length=255),
    Field('query_type', 'string', length=10),
    Field('status', 'string', length=20),  # allowed, denied, error
    Field('client_ip', 'string', length=45),
    Field('timestamp', 'datetime', default=datetime.now),
)

# Create indexes for better performance
if db._adapter.dbengine == 'sqlite':
    db.executesql('CREATE INDEX IF NOT EXISTS idx_token_domains_token ON token_domains(token_id);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_token_domains_domain ON token_domains(domain_id);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp);')

db.commit()

# Helper functions
def generate_token():
    """Generate a secure random token"""
    return secrets.token_urlsafe(32)

def check_token_permission(token_value, domain_name):
    """Check if a token has permission to access a domain"""
    token = db(db.tokens.token == token_value).select().first()
    if not token or not token.active:
        return False
    
    # Check for wildcard domain
    wildcard = db((db.token_domains.token_id == token.id) & 
                  (db.domains.id == db.token_domains.domain_id) &
                  (db.domains.name == '*')).select().first()
    if wildcard:
        return True
    
    # Check for specific domain or parent domain
    parts = domain_name.split('.')
    for i in range(len(parts)):
        check_domain = '.'.join(parts[i:])
        permission = db((db.token_domains.token_id == token.id) & 
                       (db.domains.id == db.token_domains.domain_id) &
                       (db.domains.name == check_domain)).select().first()
        if permission:
            return True
    
    return False

def log_query(token_value, domain, query_type, status, client_ip=None):
    """Log a DNS query attempt"""
    token = db(db.tokens.token == token_value).select().first()
    token_id = token.id if token else None
    
    db.query_logs.insert(
        token_id=token_id,
        domain_queried=domain,
        query_type=query_type,
        status=status,
        client_ip=client_ip
    )
    
    if token:
        token.update_record(last_used=datetime.now())
    
    db.commit()

# Web interface actions
@action('index')
@action.uses('index.html', db)
def index():
    """Dashboard showing overview statistics"""
    token_count = db(db.tokens).count()
    domain_count = db(db.domains).count()
    recent_queries = db(db.query_logs).select(
        orderby=~db.query_logs.timestamp,
        limitby=(0, 10)
    )
    
    return dict(
        token_count=token_count,
        domain_count=domain_count,
        recent_queries=recent_queries
    )

@action('tokens')
@action.uses('tokens.html', db)
def tokens_list():
    """List all tokens"""
    tokens = db(db.tokens).select(orderby=db.tokens.name)
    return dict(tokens=tokens)

@action('tokens/new', method=['GET', 'POST'])
@action.uses('token_form.html', db)
def token_new():
    """Create a new token"""
    if request.method == 'POST':
        name = request.forms.get('name')
        description = request.forms.get('description')
        token_value = request.forms.get('token') or generate_token()
        
        try:
            token_id = db.tokens.insert(
                token=token_value,
                name=name,
                description=description
            )
            db.commit()
            redirect(URL('tokens/edit', token_id))
        except Exception as e:
            response.flash = f"Error creating token: {str(e)}"
    
    return dict(token=None, generated_token=generate_token())

@action('tokens/edit/<token_id:int>', method=['GET', 'POST'])
@action.uses('token_edit.html', db)
def token_edit(token_id):
    """Edit token and manage its domain permissions"""
    token = db.tokens[token_id]
    if not token:
        abort(404)
    
    if request.method == 'POST':
        action_type = request.forms.get('action')
        
        if action_type == 'update':
            token.update_record(
                name=request.forms.get('name'),
                description=request.forms.get('description'),
                active=request.forms.get('active') == 'on'
            )
            db.commit()
            response.flash = "Token updated successfully"
        
        elif action_type == 'add_domain':
            domain_id = request.forms.get('domain_id')
            if domain_id:
                existing = db((db.token_domains.token_id == token_id) & 
                            (db.token_domains.domain_id == domain_id)).select().first()
                if not existing:
                    db.token_domains.insert(token_id=token_id, domain_id=domain_id)
                    db.commit()
        
        elif action_type == 'remove_domain':
            domain_id = request.forms.get('domain_id')
            if domain_id:
                db((db.token_domains.token_id == token_id) & 
                  (db.token_domains.domain_id == domain_id)).delete()
                db.commit()
    
    # Get current permissions
    permissions = db((db.token_domains.token_id == token_id) &
                    (db.domains.id == db.token_domains.domain_id)).select(db.domains.ALL)
    
    # Get available domains
    permitted_ids = [p.id for p in permissions]
    if permitted_ids:
        available_domains = db(~db.domains.id.belongs(permitted_ids)).select(orderby=db.domains.name)
    else:
        available_domains = db(db.domains).select(orderby=db.domains.name)
    
    return dict(
        token=token,
        permissions=permissions,
        available_domains=available_domains
    )

@action('tokens/delete/<token_id:int>')
@action.uses(db)
def token_delete(token_id):
    """Delete a token"""
    db(db.tokens.id == token_id).delete()
    db.commit()
    redirect(URL('tokens'))

@action('domains')
@action.uses('domains.html', db)
def domains_list():
    """List all domains"""
    domains = db(db.domains).select(orderby=db.domains.name)
    
    # Get token count for each domain
    domain_stats = {}
    for domain in domains:
        count = db(db.token_domains.domain_id == domain.id).count()
        domain_stats[domain.id] = count
    
    return dict(domains=domains, domain_stats=domain_stats)

@action('domains/new', method=['GET', 'POST'])
@action.uses('domain_form.html', db)
def domain_new():
    """Create a new domain"""
    if request.method == 'POST':
        name = request.forms.get('name')
        description = request.forms.get('description')
        
        try:
            db.domains.insert(name=name, description=description)
            db.commit()
            redirect(URL('domains'))
        except Exception as e:
            response.flash = f"Error creating domain: {str(e)}"
    
    return dict(domain=None)

@action('domains/edit/<domain_id:int>', method=['GET', 'POST'])
@action.uses('domain_form.html', db)
def domain_edit(domain_id):
    """Edit a domain"""
    domain = db.domains[domain_id]
    if not domain:
        abort(404)
    
    if request.method == 'POST':
        domain.update_record(
            name=request.forms.get('name'),
            description=request.forms.get('description')
        )
        db.commit()
        redirect(URL('domains'))
    
    return dict(domain=domain)

@action('domains/delete/<domain_id:int>')
@action.uses(db)
def domain_delete(domain_id):
    """Delete a domain"""
    db(db.domains.id == domain_id).delete()
    db.commit()
    redirect(URL('domains'))

@action('permissions')
@action.uses('permissions.html', db)
def permissions_matrix():
    """Show permission matrix of tokens and domains"""
    tokens = db(db.tokens).select(orderby=db.tokens.name)
    domains = db(db.domains).select(orderby=db.domains.name)
    
    # Build permission matrix
    matrix = {}
    for token in tokens:
        matrix[token.id] = {}
        for domain in domains:
            has_permission = db((db.token_domains.token_id == token.id) &
                              (db.token_domains.domain_id == domain.id)).count() > 0
            matrix[token.id][domain.id] = has_permission
    
    return dict(tokens=tokens, domains=domains, matrix=matrix)

@action('permissions/toggle', method=['POST'])
@action.uses(db)
def permission_toggle():
    """Toggle a permission via AJAX"""
    token_id = request.json.get('token_id')
    domain_id = request.json.get('domain_id')
    
    if not token_id or not domain_id:
        return dict(success=False, error="Missing parameters")
    
    existing = db((db.token_domains.token_id == token_id) &
                 (db.token_domains.domain_id == domain_id)).select().first()
    
    if existing:
        db((db.token_domains.token_id == token_id) &
          (db.token_domains.domain_id == domain_id)).delete()
        new_state = False
    else:
        db.token_domains.insert(token_id=token_id, domain_id=domain_id)
        new_state = True
    
    db.commit()
    return dict(success=True, new_state=new_state)

@action('logs')
@action.uses('logs.html', db)
def query_logs():
    """View query logs"""
    page = int(request.query.get('page', 1))
    per_page = 50
    
    limitby = ((page - 1) * per_page, page * per_page)
    
    logs = db(db.query_logs).select(
        db.query_logs.ALL,
        db.tokens.name,
        left=db.tokens.on(db.query_logs.token_id == db.tokens.id),
        orderby=~db.query_logs.timestamp,
        limitby=limitby
    )
    
    total = db(db.query_logs).count()
    total_pages = (total + per_page - 1) // per_page
    
    return dict(
        logs=logs,
        page=page,
        total_pages=total_pages,
        total=total
    )

# API endpoints for external access
@action('api/check_permission', method=['POST'])
@action.uses(db)
def api_check_permission():
    """API endpoint to check if a token has permission for a domain"""
    token = request.json.get('token')
    domain = request.json.get('domain')
    
    if not token or not domain:
        return dict(error="Missing token or domain"), 400
    
    has_permission = check_token_permission(token, domain)
    
    # Log the check
    log_query(token, domain, 'CHECK', 'allowed' if has_permission else 'denied', 
             request.environ.get('REMOTE_ADDR'))
    
    return dict(allowed=has_permission)

@action('api/tokens', method=['GET'])
@action.uses(db)
def api_tokens_list():
    """API endpoint to list all active tokens"""
    tokens = db(db.tokens.active == True).select(
        db.tokens.id,
        db.tokens.name,
        db.tokens.token,
        db.tokens.created_at
    )
    
    result = []
    for token in tokens:
        domains = db((db.token_domains.token_id == token.id) &
                    (db.domains.id == db.token_domains.domain_id)).select(db.domains.name)
        result.append({
            'id': token.id,
            'name': token.name,
            'token': token.token,
            'created_at': token.created_at.isoformat() if token.created_at else None,
            'domains': [d.name for d in domains]
        })
    
    return dict(tokens=result)

@action('api/validate/<token_value>')
@action.uses(db)
def api_validate_token(token_value):
    """API endpoint to validate a token and get its permissions"""
    token = db(db.tokens.token == token_value).select().first()
    
    if not token or not token.active:
        return dict(valid=False), 404
    
    domains = db((db.token_domains.token_id == token.id) &
                (db.domains.id == db.token_domains.domain_id)).select(db.domains.name)
    
    return dict(
        valid=True,
        name=token.name,
        domains=[d.name for d in domains]
    )