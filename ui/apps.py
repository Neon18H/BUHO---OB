import logging

from django.apps import AppConfig
from django.db.backends.signals import connection_created

logger = logging.getLogger(__name__)


class UiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ui'

    def ready(self):
        def configure_sqlite(sender, connection, **kwargs):
            if connection.vendor != 'sqlite':
                return
            with connection.cursor() as cursor:
                cursor.execute('PRAGMA journal_mode=WAL;')
                cursor.execute('PRAGMA synchronous=NORMAL;')
            logger.info('SQLite configured with WAL mode')

        connection_created.connect(configure_sqlite, dispatch_uid='ui.configure_sqlite_wal')
