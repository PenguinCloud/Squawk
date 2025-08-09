"""
DNS Console - Token and Domain Management System for Squawk
"""

from py4web import action, request, response, abort, redirect, URL, Session, Flash
from py4web.core import Fixture
from py4web.utils.auth import Auth, AuthEnforcer
from py4web.utils.form import Form, FormStyleBulma
from pydal import DAL, Field
from pydal.validators import IS_NOT_EMPTY, IS_NOT_IN_DB, IS_IN_DB, IS_MATCH, IS_EMAIL, IS_STRONG
import os
import secrets
import json
import base64
import io
import pyotp
import qrcode
from datetime import datetime, timedelta
from functools import wraps

# Database configuration
db_folder = os.path.join(os.path.dirname(__file__), 'databases')
if not os.path.exists(db_folder):
    os.makedirs(db_folder)

db = DAL(f'sqlite://dns_auth.db', folder=db_folder, pool_size=1)

# Initialize session and auth
session = Session(secret="squawk-dns-secret-" + secrets.token_hex(16))
flash = Flash()

# Configure py4web Auth
auth = Auth(session, db, define_tables=True)
auth.enable(uses=(session, flash))

# Additional auth configuration
auth_enforcer = AuthEnforcer(auth)

# Enable registration/password reset based on environment
ALLOW_REGISTRATION = os.getenv('ALLOW_REGISTRATION', 'false').lower() == 'true'
ENABLE_SSO = os.getenv('ENABLE_SSO', 'false').lower() == 'true'
SSO_PROVIDER = os.getenv('SSO_PROVIDER', 'saml')  # saml, ldap, oauth2
REQUIRE_MFA = os.getenv('REQUIRE_MFA', 'false').lower() == 'true'
MFA_ISSUER = os.getenv('MFA_ISSUER', 'Squawk DNS')

# Brute force protection settings
BRUTE_FORCE_PROTECTION = os.getenv('BRUTE_FORCE_PROTECTION', 'true').lower() == 'true'
MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
LOCKOUT_DURATION_MINUTES = int(os.getenv('LOCKOUT_DURATION_MINUTES', '30'))
ENABLE_EMAIL_NOTIFICATIONS = os.getenv('ENABLE_EMAIL_NOTIFICATIONS', 'false').lower() == 'true'

# Email configuration
SMTP_SERVER = os.getenv('SMTP_SERVER', 'localhost')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
SMTP_FROM_EMAIL = os.getenv('SMTP_FROM_EMAIL', 'noreply@squawk-dns.local')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', '')

# Configure auth settings
auth.param.registration_requires_confirmation = True
auth.param.registration_requires_approval = not ALLOW_REGISTRATION
auth.param.password_complexity = {
    "entropy": 50,  # Minimum entropy
    "length": 8,    # Minimum length
    "upper": 1,     # Uppercase letters
    "lower": 1,     # Lowercase letters  
    "digit": 1,     # Digits
    "special": 1,   # Special characters
}
auth.param.block_previous_password_num = 5  # Block reuse of last 5 passwords

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
    Field('status', 'string', length=20),  # allowed, denied, error, blocked
    Field('client_ip', 'string', length=45),
    Field('timestamp', 'datetime', default=datetime.now),
)

db.define_table('blocked_domains',
    Field('domain', 'string', length=255, unique=True, notnull=True,
          requires=[IS_NOT_EMPTY(), 
                   IS_NOT_IN_DB(db, 'blocked_domains.domain'),
                   IS_MATCH(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$',
                           error_message='Invalid domain format')]),
    Field('reason', 'text'),
    Field('added_at', 'datetime', default=datetime.now, writable=False),
    Field('added_by', 'string', length=100),
    format='%(domain)s'
)

db.define_table('blocked_ips',
    Field('ip', 'string', length=45, unique=True, notnull=True,
          requires=[IS_NOT_EMPTY(),
                   IS_NOT_IN_DB(db, 'blocked_ips.ip'),
                   IS_MATCH(r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$',
                           error_message='Invalid IP format')]),
    Field('reason', 'text'),
    Field('added_at', 'datetime', default=datetime.now, writable=False),
    Field('added_by', 'string', length=100),
    format='%(ip)s'
)

# MFA and SSO tables
db.define_table('user_mfa',
    Field('user_id', 'reference auth_user', notnull=True, ondelete='CASCADE'),
    Field('mfa_secret', 'string', length=32),  # Base32 encoded secret
    Field('backup_codes', 'text'),  # JSON array of backup codes
    Field('is_enabled', 'boolean', default=False),
    Field('setup_at', 'datetime'),
    Field('last_used', 'datetime'),
    Field('failed_attempts', 'integer', default=0),
    Field('locked_until', 'datetime'),
)

db.define_table('user_sessions',
    Field('user_id', 'reference auth_user', notnull=True, ondelete='CASCADE'),
    Field('session_token', 'string', length=64, unique=True),
    Field('ip_address', 'string', length=45),
    Field('user_agent', 'text'),
    Field('created_at', 'datetime', default=datetime.now),
    Field('last_activity', 'datetime', default=datetime.now),
    Field('expires_at', 'datetime'),
    Field('is_active', 'boolean', default=True),
    Field('mfa_verified', 'boolean', default=False),
)

db.define_table('sso_providers',
    Field('name', 'string', length=50, unique=True),
    Field('provider_type', 'string', length=20),  # saml, ldap, oauth2
    Field('config', 'text'),  # JSON configuration
    Field('is_enabled', 'boolean', default=True),
    Field('created_at', 'datetime', default=datetime.now),
)

db.define_table('audit_log',
    Field('user_id', 'reference auth_user', ondelete='SET NULL'),
    Field('action', 'string', length=50),
    Field('resource', 'string', length=100),
    Field('ip_address', 'string', length=45),
    Field('user_agent', 'text'),
    Field('details', 'text'),  # JSON details
    Field('success', 'boolean'),
    Field('timestamp', 'datetime', default=datetime.now),
)

db.define_table('login_attempts',
    Field('username', 'string', length=255),
    Field('email', 'string', length=255),
    Field('ip_address', 'string', length=45),
    Field('user_agent', 'text'),
    Field('attempt_time', 'datetime', default=datetime.now),
    Field('success', 'boolean', default=False),
    Field('failure_reason', 'string', length=100),
    Field('locked_until', 'datetime'),
)

db.define_table('security_notifications',
    Field('user_id', 'reference auth_user', ondelete='CASCADE'),
    Field('notification_type', 'string', length=50),  # account_locked, suspicious_login, etc.
    Field('message', 'text'),
    Field('sent_at', 'datetime', default=datetime.now),
    Field('email_sent', 'boolean', default=False),
    Field('ip_address', 'string', length=45),
)

# Create indexes for better performance
if db._adapter.dbengine == 'sqlite':
    db.executesql('CREATE INDEX IF NOT EXISTS idx_token_domains_token ON token_domains(token_id);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_token_domains_domain ON token_domains(domain_id);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_user_mfa_user ON user_mfa(user_id);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempt_time);')
    db.executesql('CREATE INDEX IF NOT EXISTS idx_security_notifications_user ON security_notifications(user_id);')

db.commit()

# Email notification system
class EmailNotificationManager:
    @staticmethod
    def send_email(to_email, subject, body, is_html=False):
        """Send email via SMTP or sendmail"""
        if not ENABLE_EMAIL_NOTIFICATIONS or not to_email:
            return False
            
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            from email.utils import formatdate
            
            # Create message
            msg = MIMEMultipart('alternative') if is_html else MIMEText(body)
            if is_html:
                msg.attach(MIMEText(body, 'html'))
            
            msg['From'] = SMTP_FROM_EMAIL
            msg['To'] = to_email
            msg['Subject'] = subject
            msg['Date'] = formatdate(localtime=True)
            
            # Send via SMTP or sendmail
            if SMTP_SERVER and SMTP_SERVER != 'localhost':
                # Use SMTP server
                server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
                if SMTP_USE_TLS:
                    server.starttls()
                if SMTP_USERNAME and SMTP_PASSWORD:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
                server.quit()
            else:
                # Use local sendmail
                server = smtplib.SMTP('localhost')
                server.send_message(msg)
                server.quit()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    @staticmethod
    def send_account_locked_notification(user_email, username, ip_address, lockout_minutes):
        """Send account lockout notification"""
        subject = f"Security Alert: Account Locked - {MFA_ISSUER}"
        
        body = f"""
        Security Alert: Your account has been temporarily locked due to multiple failed login attempts.
        
        Account Details:
        - Username: {username}
        - IP Address: {ip_address}
        - Lockout Duration: {lockout_minutes} minutes
        - Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        
        If this was you, please wait {lockout_minutes} minutes and try again.
        If this was not you, please contact your administrator immediately.
        
        For security reasons, do not reply to this email.
        
        --
        {MFA_ISSUER} Security System
        """
        
        return EmailNotificationManager.send_email(user_email, subject, body)
    
    @staticmethod
    def send_admin_security_alert(event_type, details):
        """Send security alert to administrator"""
        if not ADMIN_EMAIL:
            return False
            
        subject = f"Security Alert: {event_type} - {MFA_ISSUER}"
        
        body = f"""
        Security Alert: {event_type}
        
        Details:
        {details}
        
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        
        Please review the security logs for more information.
        
        --
        {MFA_ISSUER} Security System
        """
        
        return EmailNotificationManager.send_email(ADMIN_EMAIL, subject, body)

# Brute force protection manager
class BruteForceProtectionManager:
    @staticmethod
    def is_account_locked(username, ip_address=None):
        """Check if account is locked due to failed attempts"""
        if not BRUTE_FORCE_PROTECTION:
            return False, None
            
        now = datetime.now()
        
        # Check username-based lockout
        recent_attempts = db(
            (db.login_attempts.username == username) &
            (db.login_attempts.attempt_time > (now - timedelta(hours=1)))
        ).select(orderby=~db.login_attempts.attempt_time)
        
        if recent_attempts:
            latest_attempt = recent_attempts.first()
            if latest_attempt.locked_until and now < latest_attempt.locked_until:
                return True, latest_attempt.locked_until
        
        # Check IP-based lockout (optional additional protection)
        if ip_address:
            ip_attempts = db(
                (db.login_attempts.ip_address == ip_address) &
                (db.login_attempts.attempt_time > (now - timedelta(hours=1))) &
                (db.login_attempts.success == False)
            ).count()
            
            if ip_attempts >= MAX_LOGIN_ATTEMPTS * 3:  # More lenient IP-based limit
                return True, now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        
        return False, None
    
    @staticmethod
    def record_login_attempt(username, email, ip_address, user_agent, success, failure_reason=None):
        """Record a login attempt and handle lockout logic"""
        now = datetime.now()
        
        # Record the attempt
        db.login_attempts.insert(
            username=username,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            attempt_time=now,
            success=success,
            failure_reason=failure_reason
        )
        
        if success:
            # Clear any existing lockout on successful login
            db(
                (db.login_attempts.username == username) &
                (db.login_attempts.locked_until != None)
            ).update(locked_until=None)
        else:
            # Check if we need to lock the account
            if BRUTE_FORCE_PROTECTION:
                recent_failures = db(
                    (db.login_attempts.username == username) &
                    (db.login_attempts.attempt_time > (now - timedelta(hours=1))) &
                    (db.login_attempts.success == False)
                ).count()
                
                if recent_failures >= MAX_LOGIN_ATTEMPTS:
                    locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                    
                    # Update all recent attempts with lockout time
                    db(
                        (db.login_attempts.username == username) &
                        (db.login_attempts.attempt_time > (now - timedelta(hours=1)))
                    ).update(locked_until=locked_until)
                    
                    # Send notification to user and admin
                    if email:
                        EmailNotificationManager.send_account_locked_notification(
                            email, username, ip_address, LOCKOUT_DURATION_MINUTES
                        )
                    
                    # Send admin alert
                    admin_details = f"""
                    Username: {username}
                    Email: {email}
                    IP Address: {ip_address}
                    Failed Attempts: {recent_failures}
                    Lockout Duration: {LOCKOUT_DURATION_MINUTES} minutes
                    """
                    EmailNotificationManager.send_admin_security_alert(
                        "Account Locked Due to Failed Login Attempts", admin_details
                    )
                    
                    # Create security notification record
                    user = db(db.auth_user.email == email).select().first()
                    if user:
                        db.security_notifications.insert(
                            user_id=user.id,
                            notification_type='account_locked',
                            message=f'Account locked due to {recent_failures} failed login attempts',
                            ip_address=ip_address,
                            email_sent=True
                        )
                    
                    log_audit_event('account_locked', 'authentication', 
                                  {'username': username, 'attempts': recent_failures, 'ip': ip_address}, 
                                  success=False)
        
        db.commit()

# MFA Helper Functions
class MFAManager:
    @staticmethod
    def generate_secret():
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_backup_codes(count=10):
        """Generate backup codes"""
        codes = []
        for _ in range(count):
            codes.append(secrets.token_hex(4).upper())
        return codes
    
    @staticmethod
    def get_qr_code(secret, user_email):
        """Generate QR code for TOTP setup"""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=MFA_ISSUER
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for embedding in HTML
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        qr_base64 = base64.b64encode(buffer.read()).decode()
        
        return qr_base64
    
    @staticmethod
    def verify_token(secret, token):
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 30 seconds window
    
    @staticmethod
    def is_user_mfa_enabled(user_id):
        """Check if user has MFA enabled"""
        mfa_record = db(db.user_mfa.user_id == user_id).select().first()
        return mfa_record and mfa_record.is_enabled
    
    @staticmethod
    def get_user_mfa(user_id):
        """Get user's MFA record"""
        return db(db.user_mfa.user_id == user_id).select().first()

# Audit logging
def log_audit_event(action, resource, details=None, success=True):
    """Log audit event"""
    user_id = auth.current_user.get('id') if auth.current_user else None
    ip_address = request.environ.get('REMOTE_ADDR', 'unknown')
    user_agent = request.environ.get('HTTP_USER_AGENT', '')
    
    db.audit_log.insert(
        user_id=user_id,
        action=action,
        resource=resource,
        ip_address=ip_address,
        user_agent=user_agent,
        details=json.dumps(details) if details else None,
        success=success
    )
    db.commit()

# Custom authentication decorators
def require_mfa(func):
    """Decorator to require MFA verification"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not auth.current_user:
            redirect(URL('auth/login'))
        
        user_id = auth.current_user.get('id')
        
        # Check if MFA is required and enabled for user
        if REQUIRE_MFA or MFAManager.is_user_mfa_enabled(user_id):
            # Check if current session has MFA verification
            session_token = request.cookies.get('session_token')
            if session_token:
                session_record = db(db.user_sessions.session_token == session_token).select().first()
                if not session_record or not session_record.mfa_verified:
                    redirect(URL('mfa_verify'))
            else:
                redirect(URL('mfa_verify'))
        
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    """Decorator to require admin role"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not auth.current_user:
            redirect(URL('auth/login'))
        
        # Check if user has admin role (assuming role-based access)
        user_groups = auth.current_user.get('groups', [])
        if 'admin' not in user_groups and not auth.current_user.get('is_admin'):
            log_audit_event('access_denied', 'admin_area', success=False)
            abort(403, "Access denied: Admin privileges required")
        
        return func(*args, **kwargs)
    return wrapper

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

@action('blacklist')
@action.uses('blacklist.html', db)
def blacklist_management():
    """Manage blocked domains and IPs"""
    blocked_domains = db(db.blocked_domains).select(orderby=~db.blocked_domains.added_at)
    blocked_ips = db(db.blocked_ips).select(orderby=~db.blocked_ips.added_at)
    
    # Get Maravento blacklist status
    import os
    blacklist_enabled = os.getenv('ENABLE_BLACKLIST', 'false').lower() == 'true'
    update_interval = int(os.getenv('BLACKLIST_UPDATE_HOURS', '24'))
    
    return dict(
        blocked_domains=blocked_domains,
        blocked_ips=blocked_ips,
        blacklist_enabled=blacklist_enabled,
        update_interval=update_interval
    )

@action('blacklist/domain/add', method=['POST'])
@action.uses(db)
def blacklist_domain_add():
    """Add a domain to the blacklist"""
    domain = request.forms.get('domain')
    reason = request.forms.get('reason', 'Manual block')
    added_by = request.forms.get('added_by', 'Admin')
    
    try:
        db.blocked_domains.insert(
            domain=domain.lower(),
            reason=reason,
            added_by=added_by
        )
        db.commit()
        redirect(URL('blacklist'))
    except Exception as e:
        response.flash = f"Error adding domain: {str(e)}"
        redirect(URL('blacklist'))

@action('blacklist/ip/add', method=['POST'])
@action.uses(db)
def blacklist_ip_add():
    """Add an IP to the blacklist"""
    ip = request.forms.get('ip')
    reason = request.forms.get('reason', 'Manual block')
    added_by = request.forms.get('added_by', 'Admin')
    
    try:
        db.blocked_ips.insert(
            ip=ip,
            reason=reason,
            added_by=added_by
        )
        db.commit()
        redirect(URL('blacklist'))
    except Exception as e:
        response.flash = f"Error adding IP: {str(e)}"
        redirect(URL('blacklist'))

@action('blacklist/domain/delete/<domain_id:int>')
@action.uses(db)
def blacklist_domain_delete(domain_id):
    """Remove a domain from the blacklist"""
    db(db.blocked_domains.id == domain_id).delete()
    db.commit()
    redirect(URL('blacklist'))

@action('blacklist/ip/delete/<ip_id:int>')
@action.uses(db)
def blacklist_ip_delete(ip_id):
    """Remove an IP from the blacklist"""
    db(db.blocked_ips.id == ip_id).delete()
    db.commit()
    redirect(URL('blacklist'))

@action('certificates')
@action.uses('certificates.html', db)
def certificate_management():
    """Manage TLS certificates for mTLS"""
    import os
    import sys
    
    # Add the bins directory to path to import cert_manager
    bins_path = os.path.join(os.path.dirname(__file__), '..', '..', 'bins')
    if bins_path not in sys.path:
        sys.path.insert(0, bins_path)
    
    try:
        from cert_manager import CertificateManager
        cert_manager = CertificateManager()
        
        # Check if CA and server certificates exist
        ca_exists = cert_manager.ca_cert_path.exists()
        server_exists = cert_manager.server_cert_path.exists()
        
        # Get list of client certificates
        client_certs = cert_manager.list_client_certificates()
        
        # Get certificate info if they exist
        ca_info = None
        server_info = None
        
        if ca_exists:
            ca_info = cert_manager.get_certificate_info(cert_manager.ca_cert_path)
        
        if server_exists:
            server_info = cert_manager.get_certificate_info(cert_manager.server_cert_path)
        
        return dict(
            ca_exists=ca_exists,
            server_exists=server_exists,
            ca_info=ca_info,
            server_info=server_info,
            client_certs=client_certs,
            mtls_enabled=os.getenv('ENABLE_MTLS', 'false').lower() == 'true'
        )
        
    except Exception as e:
        return dict(
            error=f"Certificate manager error: {e}",
            ca_exists=False,
            server_exists=False,
            client_certs={},
            mtls_enabled=False
        )

@action('certificates/init', method=['POST'])
@action.uses(db)
def certificates_init():
    """Initialize CA and server certificates"""
    import os
    import sys
    
    bins_path = os.path.join(os.path.dirname(__file__), '..', '..', 'bins')
    if bins_path not in sys.path:
        sys.path.insert(0, bins_path)
    
    try:
        from cert_manager import CertificateManager
        cert_manager = CertificateManager()
        
        force = request.forms.get('force') == 'true'
        
        # Generate CA certificate
        ca_result = cert_manager.generate_ca_certificate(force=force)
        
        # Generate server certificate
        hostname = request.forms.get('hostname')
        ip_addresses = request.forms.get('ip_addresses', '').split(',') if request.forms.get('ip_addresses') else None
        
        server_result = cert_manager.generate_server_certificate(
            hostname=hostname if hostname else None,
            ip_addresses=ip_addresses,
            force=force
        )
        
        if ca_result or server_result:
            response.flash = "Certificates initialized successfully"
        else:
            response.flash = "Certificates already exist (use force to regenerate)"
        
    except Exception as e:
        response.flash = f"Error initializing certificates: {e}"
    
    redirect(URL('certificates'))

@action('certificates/client/new', method=['POST'])
@action.uses(db)
def client_cert_new():
    """Generate new client certificate"""
    import os
    import sys
    
    bins_path = os.path.join(os.path.dirname(__file__), '..', '..', 'bins')
    if bins_path not in sys.path:
        sys.path.insert(0, bins_path)
    
    try:
        from cert_manager import CertificateManager
        cert_manager = CertificateManager()
        
        client_name = request.forms.get('client_name')
        email = request.forms.get('email')
        force = request.forms.get('force') == 'true'
        
        if not client_name:
            response.flash = "Client name is required"
        else:
            result = cert_manager.generate_client_certificate(
                client_name,
                email=email if email else None,
                force=force
            )
            
            if result:
                response.flash = f"Client certificate generated for {client_name}"
            else:
                response.flash = f"Client certificate already exists for {client_name}"
        
    except Exception as e:
        response.flash = f"Error generating client certificate: {e}"
    
    redirect(URL('certificates'))

@action('certificates/client/revoke/<client_name>')
@action.uses(db)
def client_cert_revoke(client_name):
    """Revoke client certificate"""
    import os
    import sys
    
    bins_path = os.path.join(os.path.dirname(__file__), '..', '..', 'bins')
    if bins_path not in sys.path:
        sys.path.insert(0, bins_path)
    
    try:
        from cert_manager import CertificateManager
        cert_manager = CertificateManager()
        
        result = cert_manager.revoke_client_certificate(client_name)
        
        if result:
            response.flash = f"Client certificate revoked for {client_name}"
        else:
            response.flash = f"Client certificate not found for {client_name}"
        
    except Exception as e:
        response.flash = f"Error revoking client certificate: {e}"
    
    redirect(URL('certificates'))

@action('certificates/download/ca')
@action.uses(db)
def download_ca_cert():
    """Download CA certificate"""
    import os
    import sys
    
    bins_path = os.path.join(os.path.dirname(__file__), '..', '..', 'bins')
    if bins_path not in sys.path:
        sys.path.insert(0, bins_path)
    
    try:
        from cert_manager import CertificateManager
        cert_manager = CertificateManager()
        
        ca_path = cert_manager.export_ca_certificate()
        
        if ca_path and ca_path.exists():
            response.headers['Content-Type'] = 'application/x-x509-ca-cert'
            response.headers['Content-Disposition'] = 'attachment; filename="ca.crt"'
            
            with open(ca_path, 'rb') as f:
                return f.read()
        else:
            abort(404, "CA certificate not found")
            
    except Exception as e:
        abort(500, f"Error downloading CA certificate: {e}")

@action('certificates/download/client/<client_name>/<cert_type>')
@action.uses(db)
def download_client_cert(client_name, cert_type):
    """Download client certificate or key"""
    import os
    import sys
    
    bins_path = os.path.join(os.path.dirname(__file__), '..', '..', 'bins')
    if bins_path not in sys.path:
        sys.path.insert(0, bins_path)
    
    try:
        from cert_manager import CertificateManager
        cert_manager = CertificateManager()
        
        if cert_type == 'cert':
            file_path = cert_manager.clients_dir / f"{client_name}.crt"
            content_type = 'application/x-x509-user-cert'
            filename = f"{client_name}.crt"
        elif cert_type == 'key':
            file_path = cert_manager.clients_dir / f"{client_name}.key"
            content_type = 'application/x-iwork-keynote-sffkey'
            filename = f"{client_name}.key"
        elif cert_type == 'p12':
            file_path = cert_manager.clients_dir / f"{client_name}.p12"
            content_type = 'application/x-pkcs12'
            filename = f"{client_name}.p12"
        else:
            abort(400, "Invalid certificate type")
        
        if file_path.exists():
            response.headers['Content-Type'] = content_type
            response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            with open(file_path, 'rb') as f:
                return f.read()
        else:
            abort(404, "Certificate file not found")
            
    except Exception as e:
        abort(500, f"Error downloading certificate: {e}")

@action('certificates/download/client/<client_name>/bundle')
@action.uses(db)
def download_client_bundle(client_name):
    """Download complete client certificate bundle as ZIP"""
    import os
    import sys
    import zipfile
    import tempfile
    
    bins_path = os.path.join(os.path.dirname(__file__), '..', '..', 'bins')
    if bins_path not in sys.path:
        sys.path.insert(0, bins_path)
    
    try:
        from cert_manager import CertificateManager
        cert_manager = CertificateManager()
        
        # Create temporary zip file
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, f"{client_name}-mtls-bundle.zip")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add CA certificate
            ca_cert_path = cert_manager.ca_cert_path
            if ca_cert_path.exists():
                zipf.write(ca_cert_path, 'ca.crt')
            
            # Add client certificate
            client_cert_path = cert_manager.clients_dir / f"{client_name}.crt"
            if client_cert_path.exists():
                zipf.write(client_cert_path, f'{client_name}.crt')
            
            # Add client private key
            client_key_path = cert_manager.clients_dir / f"{client_name}.key"
            if client_key_path.exists():
                zipf.write(client_key_path, f'{client_name}.key')
            
            # Add PKCS#12 bundle if it exists
            p12_path = cert_manager.clients_dir / f"{client_name}.p12"
            if p12_path.exists():
                zipf.write(p12_path, f'{client_name}.p12')
            
            # Add configuration example
            config_content = f"""# mTLS Configuration for {client_name}
# 
# Environment Variables:
export SQUAWK_SERVER_URL=https://your-dns-server:8443
export SQUAWK_AUTH_TOKEN=your-bearer-token-here
export SQUAWK_CA_CERT=ca.crt
export SQUAWK_CLIENT_CERT={client_name}.crt
export SQUAWK_CLIENT_KEY={client_name}.key
export SQUAWK_VERIFY_SSL=true

# Command line usage:
python client.py -d example.com -s https://your-dns-server:8443 \\
  -a "your-bearer-token" \\
  --ca-cert ca.crt \\
  --client-cert {client_name}.crt \\
  --client-key {client_name}.key

# PKCS#12 bundle (contains both cert and key):
# Use {client_name}.p12 with password: squawk-dns
"""
            zipf.writestr('config-example.txt', config_content)
        
        # Read zip file and return
        with open(zip_path, 'rb') as f:
            zip_data = f.read()
        
        # Cleanup
        os.remove(zip_path)
        os.rmdir(temp_dir)
        
        response.headers['Content-Type'] = 'application/zip'
        response.headers['Content-Disposition'] = f'attachment; filename="{client_name}-mtls-bundle.zip"'
        
        log_audit_event('client_cert_bundle_download', 'certificates', 
                       {'client_name': client_name}, success=True)
        
        return zip_data
        
    except Exception as e:
        abort(500, f"Error creating certificate bundle: {e}")

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

# MFA and Authentication endpoints
@action('mfa/setup', method=['GET', 'POST'])
@action.uses('mfa_setup.html', db, auth.user, session, flash)
@auth_enforcer.requires()
def mfa_setup():
    """Setup MFA for the current user"""
    user_id = auth.current_user.get('id')
    user_email = auth.current_user.get('email')
    
    # Check if user already has MFA enabled
    existing_mfa = db(db.user_mfa.user_id == user_id).select().first()
    
    if request.method == 'POST':
        action_type = request.forms.get('action')
        
        if action_type == 'generate':
            # Generate new MFA secret
            secret = MFAManager.generate_secret()
            backup_codes = MFAManager.generate_backup_codes()
            
            # Save to database (not enabled yet)
            if existing_mfa:
                existing_mfa.update_record(
                    mfa_secret=secret,
                    backup_codes=json.dumps(backup_codes),
                    is_enabled=False,
                    setup_at=datetime.now(),
                    failed_attempts=0,
                    locked_until=None
                )
            else:
                db.user_mfa.insert(
                    user_id=user_id,
                    mfa_secret=secret,
                    backup_codes=json.dumps(backup_codes),
                    is_enabled=False,
                    setup_at=datetime.now()
                )
            db.commit()
            
            # Generate QR code
            qr_code = MFAManager.get_qr_code(secret, user_email)
            
            log_audit_event('mfa_setup_started', 'user_mfa')
            
            return dict(
                step='verify',
                secret=secret,
                qr_code=qr_code,
                backup_codes=backup_codes,
                issuer=MFA_ISSUER,
                user_email=user_email
            )
        
        elif action_type == 'verify':
            # Verify MFA token and enable
            token = request.forms.get('token')
            secret = request.forms.get('secret')
            
            if MFAManager.verify_token(secret, token):
                # Enable MFA
                mfa_record = db(db.user_mfa.user_id == user_id).select().first()
                if mfa_record:
                    mfa_record.update_record(
                        is_enabled=True,
                        last_used=datetime.now()
                    )
                    db.commit()
                    
                    log_audit_event('mfa_enabled', 'user_mfa', {'secret_length': len(secret)})
                    flash.set('MFA successfully enabled!')
                    redirect(URL('index'))
                else:
                    flash.set('MFA setup error. Please try again.', 'error')
            else:
                flash.set('Invalid verification code. Please try again.', 'error')
                return dict(step='verify', secret=secret, error=True)
        
        elif action_type == 'disable':
            # Disable MFA (requires current password)
            password = request.forms.get('password')
            if auth.verify_password(password):
                if existing_mfa:
                    existing_mfa.update_record(is_enabled=False)
                    db.commit()
                    log_audit_event('mfa_disabled', 'user_mfa')
                    flash.set('MFA has been disabled.')
                    redirect(URL('index'))
            else:
                flash.set('Invalid password. Cannot disable MFA.', 'error')
    
    # GET request - show current MFA status
    mfa_enabled = existing_mfa and existing_mfa.is_enabled if existing_mfa else False
    return dict(
        step='initial',
        mfa_enabled=mfa_enabled,
        setup_date=existing_mfa.setup_at if existing_mfa else None
    )

@action('mfa/verify', method=['GET', 'POST'])
@action.uses('mfa_verify.html', db, session, flash)
def mfa_verify():
    """Verify MFA token for login"""
    if not auth.current_user:
        redirect(URL('auth/login'))
    
    user_id = auth.current_user.get('id')
    user_email = auth.current_user.get('email', '')
    username = auth.current_user.get('username', auth.current_user.get('email', ''))
    ip_address = request.environ.get('REMOTE_ADDR', 'unknown')
    user_agent = request.environ.get('HTTP_USER_AGENT', '')
    
    # Check if account is locked due to brute force protection
    is_locked, lock_time = BruteForceProtectionManager.is_account_locked(username, ip_address)
    if is_locked:
        return dict(
            locked=True,
            lock_time=lock_time,
            failed_attempts=MAX_LOGIN_ATTEMPTS
        )
    
    if request.method == 'POST':
        token = request.forms.get('token')
        
        # Check for backup code
        if token and len(token) == 8 and token.isupper():
            mfa_record = db(db.user_mfa.user_id == user_id).select().first()
            if mfa_record and mfa_record.backup_codes:
                backup_codes = json.loads(mfa_record.backup_codes)
                if token in backup_codes:
                    # Remove used backup code
                    backup_codes.remove(token)
                    mfa_record.update_record(
                        backup_codes=json.dumps(backup_codes),
                        last_used=datetime.now()
                    )
                    db.commit()
                    
                    # Record successful MFA attempt
                    BruteForceProtectionManager.record_login_attempt(
                        username, user_email, ip_address, user_agent, True
                    )
                    
                    # Create verified session
                    session_token = secrets.token_hex(32)
                    db.user_sessions.insert(
                        user_id=user_id,
                        session_token=session_token,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        expires_at=datetime.now() + timedelta(hours=8),
                        mfa_verified=True
                    )
                    db.commit()
                    
                    response.set_cookie('session_token', session_token, secure=True, httponly=True)
                    log_audit_event('mfa_backup_code_used', 'authentication')
                    flash.set('Backup code accepted.')
                    redirect(URL('index'))
                else:
                    # Record failed backup code attempt
                    BruteForceProtectionManager.record_login_attempt(
                        username, user_email, ip_address, user_agent, False, 'invalid_backup_code'
                    )
                    flash.set('Invalid backup code.', 'error')
                    log_audit_event('mfa_backup_code_invalid', 'authentication', success=False)
        else:
            # Verify TOTP token
            mfa_record = db(db.user_mfa.user_id == user_id).select().first()
            if mfa_record and MFAManager.verify_token(mfa_record.mfa_secret, token):
                # Update MFA record
                mfa_record.update_record(
                    last_used=datetime.now(),
                    failed_attempts=0,
                    locked_until=None
                )
                
                # Record successful MFA attempt
                BruteForceProtectionManager.record_login_attempt(
                    username, user_email, ip_address, user_agent, True
                )
                
                # Create verified session
                session_token = secrets.token_hex(32)
                db.user_sessions.insert(
                    user_id=user_id,
                    session_token=session_token,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    expires_at=datetime.now() + timedelta(hours=8),
                    mfa_verified=True
                )
                db.commit()
                
                response.set_cookie('session_token', session_token, secure=True, httponly=True)
                log_audit_event('mfa_verification_success', 'authentication')
                flash.set('MFA verification successful.')
                redirect(URL('index'))
            else:
                # Handle failed MFA attempt
                BruteForceProtectionManager.record_login_attempt(
                    username, user_email, ip_address, user_agent, False, 'invalid_mfa_token'
                )
                
                # Update MFA record
                if mfa_record:
                    failed_attempts = (mfa_record.failed_attempts or 0) + 1
                    locked_until = None
                    
                    if failed_attempts >= 5:
                        locked_until = datetime.now() + timedelta(minutes=30)
                    
                    mfa_record.update_record(
                        failed_attempts=failed_attempts,
                        locked_until=locked_until
                    )
                    db.commit()
                
                flash.set('Invalid verification code.', 'error')
                log_audit_event('mfa_verification_failed', 'authentication', success=False)
    
    # Check if account is locked (MFA-specific lockout)
    mfa_record = db(db.user_mfa.user_id == user_id).select().first()
    mfa_locked = False
    if mfa_record and mfa_record.locked_until:
        if datetime.now() < mfa_record.locked_until:
            mfa_locked = True
        else:
            # Unlock account
            mfa_record.update_record(locked_until=None, failed_attempts=0)
            db.commit()
    
    return dict(
        locked=mfa_locked,
        lock_time=mfa_record.locked_until if mfa_record else None,
        failed_attempts=mfa_record.failed_attempts if mfa_record else 0
    )

@action('auth/sso/login/<provider>')
@action.uses(db, session)
def sso_login(provider):
    """Initiate SSO login with specified provider"""
    if not ENABLE_SSO:
        abort(404, "SSO not enabled")
    
    # Get provider configuration
    sso_provider = db(
        (db.sso_providers.name == provider) & 
        (db.sso_providers.is_enabled == True)
    ).select().first()
    
    if not sso_provider:
        abort(404, "SSO provider not found")
    
    config = json.loads(sso_provider.config)
    
    if sso_provider.provider_type == 'saml':
        # SAML SSO implementation
        return redirect(config.get('sso_url', '/'))
    elif sso_provider.provider_type == 'ldap':
        # LDAP authentication redirect to form
        session['sso_provider'] = provider
        redirect(URL('auth/sso/ldap'))
    elif sso_provider.provider_type == 'oauth2':
        # OAuth2 flow initiation
        return redirect(config.get('auth_url', '/'))
    
    abort(400, "Unsupported SSO provider type")

@action('auth/sso/ldap', method=['GET', 'POST'])
@action.uses('ldap_login.html', db, session, flash)
def ldap_login():
    """LDAP authentication form"""
    if not ENABLE_SSO or session.get('sso_provider') != 'ldap':
        abort(404)
    
    if request.method == 'POST':
        username = request.forms.get('username')
        password = request.forms.get('password')
        
        # LDAP authentication logic would go here
        # For now, just log the attempt
        log_audit_event('ldap_auth_attempt', 'sso_authentication', 
                       {'username': username}, success=True)
        
        flash.set('LDAP authentication not yet implemented.')
        redirect(URL('index'))
    
    return dict()

@action('admin/sso', method=['GET', 'POST'])
@action.uses('sso_config.html', db, auth.user, session, flash)
@admin_required
def sso_configuration():
    """Admin interface for SSO provider configuration"""
    
    if request.method == 'POST':
        action_type = request.forms.get('action')
        
        if action_type == 'add_provider':
            name = request.forms.get('name')
            provider_type = request.forms.get('provider_type')
            config_json = request.forms.get('config')
            
            try:
                # Validate JSON configuration
                config = json.loads(config_json)
                
                db.sso_providers.insert(
                    name=name,
                    provider_type=provider_type,
                    config=config_json,
                    is_enabled=True
                )
                db.commit()
                
                log_audit_event('sso_provider_added', 'sso_config', 
                               {'provider': name, 'type': provider_type})
                flash.set(f'SSO provider {name} added successfully.')
                
            except json.JSONDecodeError:
                flash.set('Invalid JSON configuration.', 'error')
            except Exception as e:
                flash.set(f'Error adding provider: {e}', 'error')
        
        elif action_type == 'toggle_provider':
            provider_id = int(request.forms.get('provider_id'))
            provider = db.sso_providers[provider_id]
            if provider:
                provider.update_record(is_enabled=not provider.is_enabled)
                db.commit()
                
                status = 'enabled' if provider.is_enabled else 'disabled'
                log_audit_event('sso_provider_toggled', 'sso_config',
                               {'provider_id': provider_id, 'status': status})
                flash.set(f'Provider {status} successfully.')
    
    providers = db(db.sso_providers).select(orderby=db.sso_providers.name)
    
    return dict(
        providers=providers,
        sso_enabled=ENABLE_SSO,
        sso_provider_type=SSO_PROVIDER
    )