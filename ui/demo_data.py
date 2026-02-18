from datetime import timedelta

from django.utils import timezone


SERVER_STATUSES = ['Online', 'Offline', 'Degraded']
LOG_LEVELS = ['INFO', 'WARN', 'ERROR']
SEVERITIES = ['Low', 'Medium', 'High', 'Critical']


def get_servers():
    now = timezone.now()
    return [
        {
            'id': idx,
            'hostname': f'app-node-{idx:02d}',
            'ip': f'10.0.0.{idx}',
            'os': 'Ubuntu 22.04',
            'status': SERVER_STATUSES[idx % len(SERVER_STATUSES)],
            'last_seen': now - timedelta(minutes=idx * 5),
        }
        for idx in range(1, 13)
    ]


def get_apps():
    return [
        {'name': 'nginx', 'version': '1.25', 'host': 'app-node-01', 'status': 'Running'},
        {'name': 'postgresql', 'version': '16', 'host': 'db-node-01', 'status': 'Running'},
        {'name': 'redis', 'version': '7', 'host': 'cache-node-01', 'status': 'Running'},
        {'name': 'celery', 'version': '5.4', 'host': 'worker-node-01', 'status': 'Degraded'},
    ]


def get_logs():
    base = timezone.now()
    entries = []
    for idx in range(1, 41):
        level = LOG_LEVELS[idx % len(LOG_LEVELS)]
        entries.append(
            {
                'id': idx,
                'timestamp': base - timedelta(minutes=idx * 3),
                'source': f'app-node-{(idx % 8) + 1:02d}',
                'level': level,
                'message': f'Event {idx}: simulated {level.lower()} message for dashboard testing.',
            }
        )
    return entries


def get_alerts():
    return [
        {'id': 1, 'title': 'CPU spike on app-node-03', 'severity': 'High', 'status': 'Open'},
        {'id': 2, 'title': 'Disk usage > 90% on db-node-01', 'severity': 'Critical', 'status': 'Ack'},
        {'id': 3, 'title': 'Service restart detected', 'severity': 'Medium', 'status': 'Resolved'},
    ]
