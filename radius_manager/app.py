from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
from config import Config
import logging
import time
import re
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets

app = Flask(__name__)
app.config.from_object(Config)

# Initialize logging
Config.init_logging()
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length for hash
    email = db.Column(db.String(120), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_password(self, password):
        """Hash password before storing"""
        self.password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password):
        """Check password against stored hash"""
        return check_password_hash(self.password, password)
    
    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False
    
    def increment_failed_login(self):
        """Increment failed login attempts and lock if needed"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= Config.MAX_FAILED_LOGINS:
            self.locked_until = datetime.utcnow() + timedelta(seconds=Config.ACCOUNT_LOCKOUT_DURATION)
            logger.warning(f"User {self.username} locked until {self.locked_until}")
    
    def reset_failed_login(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.locked_until = None

class RadCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    attribute = db.Column(db.String(64), nullable=False)
    op = db.Column(db.String(2), nullable=False)
    value = db.Column(db.String(253), nullable=False)

class RadAcct(db.Model):
    radacctid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    acctstarttime = db.Column(db.DateTime)
    acctstoptime = db.Column(db.DateTime)
    nasipaddress = db.Column(db.String(15))
    framedipaddress = db.Column(db.String(15))
    acctterminatecause = db.Column(db.String(32))

class NASClient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nasname = db.Column(db.String(128), nullable=False)
    shortname = db.Column(db.String(32), nullable=False)
    secret = db.Column(db.String(64), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Add a small delay to prevent brute force attacks
        time.sleep(Config.FAILED_LOGIN_DELAY)
        
        user = User.query.filter_by(username=username).first()
        login_failed = True
        
        if user:
            # Check if account is locked
            if user.is_locked():
                flash(f'Account is locked due to too many failed attempts. Try again later.')
                logger.warning(f"Login attempt on locked account: {username}")
                return render_template('login.html')
            
            # Check password
            if user.check_password(password):
                login_failed = False
                # Reset failed login attempts
                user.reset_failed_login()
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                # Log successful login
                logger.info(f"User {username} logged in successfully")
                
                # Set session expiry
                session.permanent = True
                app.permanent_session_lifetime = timedelta(seconds=Config.SESSION_TIMEOUT)
                
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
        
        if login_failed:
            # Log failed login attempt
            logger.warning(f"Failed login attempt for user: {username}")
            
            if user:
                # Increment failed login attempts
                user.increment_failed_login()
                db.session.commit()
            
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/users')
@login_required
def users():
    radius_users = RadCheck.query.filter_by(attribute='Cleartext-Password').all()
    return render_template('users.html', users=radius_users)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate password strength
        if not validate_password(password):
            flash('Password does not meet security requirements')
            return render_template('add_user.html')
        
        # Hash password for RADIUS
        hashed_password = generate_password_hash(password, method='md5')
        
        # Add user to RadCheck table with hashed password
        new_user = RadCheck(
            username=username,
            attribute='MD5-Password',  # Using MD5 for RADIUS compatibility
            op=':=',
            value=hashed_password.replace('md5$', '')  # Remove prefix for RADIUS
        )
        
        # Add session limit
        session_limit = RadCheck(
            username=username,
            attribute='Simultaneous-Use',
            op=':=',
            value=str(Config.MAX_SESSIONS_PER_USER)  # Session limit from config
        )
        
        # Add session timeout
        session_timeout = RadCheck(
            username=username,
            attribute='Session-Timeout',
            op=':=',
            value=str(Config.SESSION_TIMEOUT)
        )
        
        # Add idle timeout
        idle_timeout = RadCheck(
            username=username,
            attribute='Idle-Timeout',
            op=':=',
            value=str(Config.SESSION_IDLE_TIMEOUT)
        )
        
        try:
            db.session.add(new_user)
            db.session.add(session_limit)
            db.session.add(session_timeout)
            db.session.add(idle_timeout)
            db.session.commit()
            
            logger.info(f"User {username} added successfully by {current_user.username}")
            flash('User added successfully')
            return redirect(url_for('users'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding user {username}: {str(e)}")
            flash(f'Error adding user: {str(e)}')
    
    return render_template('add_user.html')

@app.route('/nas_clients')
@login_required
def nas_clients():
    clients = NASClient.query.all()
    return render_template('nas_clients.html', clients=clients)

@app.route('/add_nas', methods=['GET', 'POST'])
@login_required
def add_nas():
    if request.method == 'POST':
        nasname = request.form['nasname']
        shortname = request.form['shortname']
        secret = request.form.get('secret', '')
        
        # Generate a random secret if not provided
        if not secret:
            secret = generate_nas_secret()
        
        new_client = NASClient(
            nasname=nasname,
            shortname=shortname,
            secret=secret
        )
        
        try:
            db.session.add(new_client)
            db.session.commit()
            logger.info(f"NAS client {shortname} ({nasname}) added by {current_user.username}")
            flash('NAS client added successfully')
            return redirect(url_for('nas_clients'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding NAS client {shortname}: {str(e)}")
            flash(f'Error adding NAS client: {str(e)}')
    
    return render_template('add_nas.html')

@app.route('/active_sessions')
@login_required
def active_sessions():
    sessions = RadAcct.query.filter_by(acctstoptime=None).all()
    return render_template('active_sessions.html', sessions=sessions)

# Helper functions
def validate_password(password):
    """Validate password against security requirements"""
    if len(password) < Config.PASSWORD_MIN_LENGTH:
        return False
    
    if Config.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False
    
    if Config.PASSWORD_REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
        return False
    
    if Config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    
    return True

def generate_nas_secret(length=None):
    """Generate a secure random secret for NAS clients"""
    if length is None:
        length = Config.DEFAULT_NAS_SECRET_LENGTH
    return secrets.token_urlsafe(length)

@app.route('/logout')
@login_required
def logout():
    logger.info(f"User {current_user.username} logged out")
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(Config.LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username=Config.ADMIN_USERNAME).first()
        if not admin:
            admin = User(username=Config.ADMIN_USERNAME, is_admin=True)
            admin.set_password(Config.ADMIN_PASSWORD)  # Use password hashing
            admin.email = Config.ADMIN_EMAIL
            db.session.add(admin)
            db.session.commit()
            logger.info(f"Admin user {Config.ADMIN_USERNAME} created at startup")
    
    logger.info(f"Starting RADIUS Manager on {Config.SERVER_HOST}:{Config.SERVER_PORT}")
    app.run(
        host=Config.SERVER_HOST,
        port=Config.SERVER_PORT,
        debug=Config.DEBUG
    )
