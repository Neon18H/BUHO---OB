import logging
import os

from django.core.wsgi import get_wsgi_application

from .runtime import get_db_label

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'buho.settings')

application = get_wsgi_application()

logger = logging.getLogger(__name__)
logger.info('Buho startup database backend: %s', get_db_label())
from django.conf import settings  # noqa: E402
logger.info('Buho startup public host: %s', settings.BUHO_PUBLIC_URL or 'request-derived')
