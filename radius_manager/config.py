from dotenv import load_dotenv
import os
from pathlib import Path
import logging
import logging.handlers

# Load environment variables from .env file
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

def get_bool_env(key, default='False'):
    return os.getenv(key, default).lower() == 'true'

def get_int_env(key, default):
    return int(os.getenv(key, default))

class Config:
    # Flask Configuration
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', os.urandom(24))
    DEBUG = get_bool_env('FLASK_DEBUG')
    PERMANENT_SESSION_LIFETIME = get_int_env('FLASK_SESSION_LIFETIME', '3600')

    # Database Configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = get_int_env('DB_PORT', '3306')
    DB_NAME = os.getenv('DB_NAME', 'radius')
    DB_USER = os.getenv('DB_USER', 'radius')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'radius')
    DB_POOL_SIZE = get_int_env('DB_POOL_SIZE', '10')
    DB_POOL_TIMEOUT = get_int_env('DB_POOL_TIMEOUT', '30')
    
    # SQLAlchemy Configuration
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': DB_POOL_SIZE,
        'pool_timeout': DB_POOL_TIMEOUT
    }

    # Admin User Configuration
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@example.com')

    # User Password Configuration
    PASSWORD_MIN_LENGTH = get_int_env('PASSWORD_MIN_LENGTH', '8')
    PASSWORD_REQUIRE_UPPERCASE = get_bool_env('PASSWORD_REQUIRE_UPPERCASE')
    PASSWORD_REQUIRE_NUMBERS = get_bool_env('PASSWORD_REQUIRE_NUMBERS')
    PASSWORD_REQUIRE_SPECIAL = get_bool_env('PASSWORD_REQUIRE_SPECIAL')
    PASSWORD_HASH_ROUNDS = get_int_env('PASSWORD_HASH_ROUNDS', '100000')

    # RADIUS Configuration
    RADIUS_SECRET = os.getenv('RADIUS_SECRET', 'testing123')
    RADIUS_NAS_TYPE = os.getenv('RADIUS_NAS_TYPE', 'other')
    RADIUS_AUTH_PORT = get_int_env('RADIUS_AUTH_PORT', '1812')
    RADIUS_ACCT_PORT = get_int_env('RADIUS_ACCT_PORT', '1813')
    RADIUS_REQUEST_TIMEOUT = get_int_env('RADIUS_REQUEST_TIMEOUT', '5')
    RADIUS_MAX_RETRY = get_int_env('RADIUS_MAX_RETRY', '3')
    RADIUS_DICTIONARY_DIR = os.getenv('RADIUS_DICTIONARY_DIR', '/etc/freeradius/3.0/dictionary')

    # Session Configuration
    MAX_SESSIONS_PER_USER = get_int_env('MAX_SESSIONS_PER_USER', '1')
    SESSION_TIMEOUT = get_int_env('SESSION_TIMEOUT', '3600')
    SESSION_IDLE_TIMEOUT = get_int_env('SESSION_IDLE_TIMEOUT', '600')
    SESSION_CLEANUP_INTERVAL = get_int_env('SESSION_CLEANUP_INTERVAL', '300')

    # Server Configuration
    SERVER_HOST = os.getenv('SERVER_HOST', '127.0.0.1')
    SERVER_PORT = get_int_env('SERVER_PORT', '5000')
    SERVER_WORKERS = get_int_env('SERVER_WORKERS', '4')
    SERVER_THREADS = get_int_env('SERVER_THREADS', '2')

    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    LOG_FILE = os.getenv('LOG_FILE', '/var/log/radius_manager/app.log')
    LOG_MAX_SIZE = get_int_env('LOG_MAX_SIZE', '10485760')  # 10MB
    LOG_BACKUP_COUNT = get_int_env('LOG_BACKUP_COUNT', '5')

    # Security Configuration
    ALLOW_PASSWORD_RESET = get_bool_env('ALLOW_PASSWORD_RESET')
    PASSWORD_RESET_TIMEOUT = get_int_env('PASSWORD_RESET_TIMEOUT', '3600')
    FAILED_LOGIN_DELAY = get_int_env('FAILED_LOGIN_DELAY', '2')
    MAX_FAILED_LOGINS = get_int_env('MAX_FAILED_LOGINS', '5')
    ACCOUNT_LOCKOUT_DURATION = get_int_env('ACCOUNT_LOCKOUT_DURATION', '1800')

    # Email Configuration
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = get_int_env('SMTP_PORT', '587')
    SMTP_USE_TLS = get_bool_env('SMTP_USE_TLS')
    SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
    EMAIL_FROM = os.getenv('EMAIL_FROM', '')

    # RADIUS EAP Configuration
    EAP_DEFAULT_TYPE = os.getenv('EAP_DEFAULT_TYPE', 'peap')
    EAP_PRIVATE_KEY_FILE = os.getenv('EAP_PRIVATE_KEY_FILE', '/etc/freeradius/3.0/certs/server.key')
    EAP_CERTIFICATE_FILE = os.getenv('EAP_CERTIFICATE_FILE', '/etc/freeradius/3.0/certs/server.pem')
    EAP_CA_FILE = os.getenv('EAP_CA_FILE', '/etc/freeradius/3.0/certs/ca.pem')
    EAP_DH_FILE = os.getenv('EAP_DH_FILE', '/etc/freeradius/3.0/certs/dh')
    EAP_FRAGMENT_SIZE = get_int_env('EAP_FRAGMENT_SIZE', '1024')

    # NAS Client Default Configuration
    DEFAULT_NAS_SECRET_LENGTH = get_int_env('DEFAULT_NAS_SECRET_LENGTH', '32')
    DEFAULT_NAS_REQUIRE_MESSAGE_AUTHENTICATOR = get_bool_env('DEFAULT_NAS_REQUIRE_MESSAGE_AUTHENTICATOR')
    DEFAULT_NAS_TIMEOUT = get_int_env('DEFAULT_NAS_TIMEOUT', '3')
    DEFAULT_NAS_RETRIES = get_int_env('DEFAULT_NAS_RETRIES', '2')

    @classmethod
    def init_logging(cls):
        """Initialize logging configuration"""
        log_dir = os.path.dirname(cls.LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        logging.basicConfig(
            level=getattr(logging, cls.LOG_LEVEL.upper()),
            format=cls.LOG_FORMAT,
            handlers=[
                logging.handlers.RotatingFileHandler(
                    cls.LOG_FILE,
                    maxBytes=cls.LOG_MAX_SIZE,
                    backupCount=cls.LOG_BACKUP_COUNT
                ),
                logging.StreamHandler()
            ]
        )
