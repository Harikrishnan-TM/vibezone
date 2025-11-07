import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()
import dj_database_url  # Make sure you install thiis package







# Triggering deploy hkjh

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SECRET_KEY")


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

APPEND_SLASH = False  # ✅ Disable automatic redirect for /health

default_hosts = 'localhost,127.0.0.1,::1,.ngrok-free.app'

ALLOWED_HOSTS = [host.strip() for host in os.getenv('ALLOWED_HOSTS', default_hosts).split(',')] + ['172.19.2.162']



print(">>> ENV ALLOWED_HOSTS:", os.getenv("ALLOWED_HOSTS"))




# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app',
    'corsheaders',
    'channels',
    'rest_framework',
    'rest_framework.authtoken',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
}

ASGI_APPLICATION = "core.asgi.application"

# Redis backend for Channels new new
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [{
                "address": "rediss://default:AXDNAAIjcDEwZGVjOGQ1MmI5M2Y0OGU2YmQzOThkYzRmNjA3OTMyYnAxMA@grateful-coyote-28877.upstash.io:6379",
                "health_check_interval": 10,
                "socket_connect_timeout": 5,
                "retry_on_timeout": True,
                "socket_keepalive": True,
            }],
        },
    },
}


# Redirect URLs for auth
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'home'
LOGOUT_REDIRECT_URL = 'login'

MIDDLEWARE = [
    
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'core', 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
load_dotenv()

# Get environment type
ENVIRONMENT = os.getenv('DJANGO_ENV', 'development')

# Configure database based on environment
if ENVIRONMENT == 'production':
    DATABASE_URL = os.getenv("DATABASE_URL")
    if DATABASE_URL:
        DATABASES = {
            'default': dj_database_url.parse(DATABASE_URL)
        }
    else:
        raise Exception("DATABASE_URL is not set in the environment.")
else:
    # Default to SQLite for development
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }



# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'core', 'static')]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom User model
AUTH_USER_MODEL = 'app.User'

# Agora Configuration
AGORA_APP_ID = os.getenv("AGORA_APP_ID")
AGORA_APP_CERTIFICATE = os.getenv("AGORA_APP_CERTIFICATE")


# CORS Configuration - restrict origins in productionjkhkhjkdhsd
CORS_ALLOW_ALL_ORIGINS = False  # Set to False in production
CORS_ALLOWED_ORIGINS = [
    "https://vibezone.app",
    "https://techno-official.github.io",
    "https://www.vibzeoofficial.in",
    "https://vibzeoofficial.in",  # ✅ Where your Flutter web app will live
]

STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'



# Update for security and production


SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

SECURE_SSL_REDIRECT = not DEBUG  # Redirect to HTTPS in production
CSRF_COOKIE_SECURE = not DEBUG  # CSRF protection over HTTPS in production
SESSION_COOKIE_SECURE = not DEBUG  # Secure session cookies in production
SECURE_HSTS_SECONDS = 31536000  # One year, adjust as needed
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True



LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',  # Change to DEBUG if needed
    },
}


#For website payment



RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")



SECRET_TAX_TOKEN = os.getenv("SECRET_TAX_TOKEN")


TIME_ZONE = 'Asia/Kolkata'
USE_TZ = True

# Email setup


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.mailersend.net'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
 # Use API key as SMTP password
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'support@techzniczone.com')


# Email setup


# -------------- ✅ SECURITY SETTINGS START ------------------

# 🛡️ Brute-force login protection (django-axes)
INSTALLED_APPS += ['axes']
MIDDLEWARE.insert(0, 'axes.middleware.AxesMiddleware')  # Insert early in the chain

AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesBackend',
    'django.contrib.auth.backends.ModelBackend',
]

AXES_FAILURE_LIMIT = 5              # Max 5 failed login attempts
AXES_COOLOFF_TIME = 1               # Lock for 1 hour
#AXES_LOCKOUT_PARAMETERS = ['ip']    # Lock by IP
AXES_LOCKOUT_PARAMETERS = ['username', 'ip_address']

# 🧱 Optional: Rate limit other APIs (django-ratelimit)
# Use @ratelimit(key='ip', rate='10/m', block=True) on your views

# 🕵️ Security Headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# 🧼 Cookie & Session Hardening
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# -------------- ✅ SECURITY SETTINGS END --------------------
