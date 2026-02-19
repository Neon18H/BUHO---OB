from django.conf import settings


def get_public_base_url(request=None) -> str:
    configured = (getattr(settings, 'BUHO_PUBLIC_URL', '') or '').strip().rstrip('/')
    if configured:
        return configured
    if request is not None:
        return request.build_absolute_uri('/').rstrip('/')
    return ''


def get_db_label() -> str:
    engine = (settings.DATABASES.get('default', {}).get('ENGINE') or '').lower()
    if 'postgresql' in engine or 'postgres' in engine:
        return 'postgres'
    return 'sqlite'
