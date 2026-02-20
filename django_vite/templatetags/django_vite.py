import json
from pathlib import Path

from django import template
from django.conf import settings
from django.templatetags.static import static
from django.utils.safestring import mark_safe

register = template.Library()


def _manifest():
    manifest_path = Path(getattr(settings, 'VITE_MANIFEST_PATH', ''))
    if manifest_path.exists():
        return json.loads(manifest_path.read_text())
    return {}


@register.simple_tag
def vite_hmr_client():
    if settings.DEBUG:
        server = getattr(settings, 'VITE_DEV_SERVER', 'http://localhost:5173')
        return mark_safe(f'<script type="module" src="{server}/@vite/client"></script>')
    return ''


@register.simple_tag
def vite_asset(entry: str):
    if settings.DEBUG:
        server = getattr(settings, 'VITE_DEV_SERVER', 'http://localhost:5173')
        return mark_safe(f'<script type="module" src="{server}/{entry}"></script>')

    data = _manifest().get(entry, {})
    tags = []
    css_files = data.get('css', [])
    for css in css_files:
        tags.append(f'<link rel="stylesheet" href="{static("vite/" + css)}">')
    file_name = data.get('file')
    if file_name:
        tags.append(f'<script type="module" src="{static("vite/" + file_name)}"></script>')
    return mark_safe(''.join(tags))
