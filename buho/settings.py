import importlib.util
import logging
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 't', 'yes', 'y', 'on'}


def env_list(name: str):
    raw = os.getenv(name, '')
    return [item.strip() for item in raw.split(',') if item.strip()]


SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-buho-local-dev-secret-key')
DEBUG = env_bool('DEBUG', default=False)

allowed_hosts = env_list('ALLOWED_HOSTS')
if not allowed_hosts:
    if DEBUG:
        allowed_hosts = ['*']
    else:
        railway_host = os.getenv('RAILWAY_PUBLIC_DOMAIN') or os.getenv('RAILWAY_STATIC_URL', '').replace('https://', '').replace('http://', '').strip('/')
        allowed_hosts = [railway_host] if railway_host else ['localhost', '127.0.0.1', 'testserver']
ALLOWED_HOSTS = allowed_hosts

CSRF_TRUSTED_ORIGINS = env_list('CSRF_TRUSTED_ORIGINS')

BUHO_PUBLIC_URL = os.getenv('BUHO_PUBLIC_URL', '').strip().rstrip('/')

HAS_WHITENOISE = importlib.util.find_spec('whitenoise') is not None

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'audit',
    'ui',
    'agents',
    'dashboards',
    'rest_framework',
    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
if HAS_WHITENOISE:
    MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')

ROOT_URLCONF = 'buho.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'ui.context_processors.active_organization',
            ],
        },
    },
]

WSGI_APPLICATION = 'buho.wsgi.application'

database_url = os.getenv('DATABASE_URL', '').strip()
if database_url:
    import dj_database_url

    DATABASES = {
        'default': dj_database_url.config(default=database_url, conn_max_age=60, ssl_require=True),
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
if HAS_WHITENOISE:
    STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'accounts.User'
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'ui:overview'
LOGOUT_REDIRECT_URL = 'accounts:login'

ROLE_HIERARCHY = {
    'SUPERADMIN': 4,
    'ORG_ADMIN': 3,
    'ANALYST': 2,
    'VIEWER': 1,
}

RETENTION_DAYS = 7
AGENT_OFFLINE_SECONDS = 90

logging.getLogger(__name__).debug('Buho settings loaded (debug=%s, allowed_hosts=%s)', DEBUG, ALLOWED_HOSTS)
