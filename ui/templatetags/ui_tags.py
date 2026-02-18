from django import template

register = template.Library()


@register.filter
def badge_class(value):
    mapping = {
        'Online': 'success',
        'Offline': 'danger',
        'Degraded': 'warning',
        'Open': 'danger',
        'Ack': 'warning',
        'Resolved': 'success',
        'Low': 'info',
        'Medium': 'warning',
        'High': 'danger',
        'Critical': 'dark',
        'INFO': 'info',
        'WARN': 'warning',
        'ERROR': 'danger',
    }
    return mapping.get(value, 'secondary')
