from datetime import timedelta

from django.utils import timezone

from .models import LogEntry, MetricPoint


def calculate_agent_health(agent):
    score = 100
    reasons = []
    now = timezone.now()
    if not agent.last_seen or agent.last_seen < now - timedelta(minutes=2):
        score -= 35
        reasons.append('offline_or_stale_heartbeat')

    recent_metrics = MetricPoint.objects.filter(agent=agent, organization=agent.organization, ts__gte=now - timedelta(minutes=15))
    cpu = recent_metrics.filter(name='cpu.percent').order_by('-ts').values_list('value', flat=True).first()
    mem = recent_metrics.filter(name='mem.percent').order_by('-ts').values_list('value', flat=True).first()
    disk = recent_metrics.filter(name='disk.root.used_percent').order_by('-ts').values_list('value', flat=True).first()

    if cpu and cpu >= 90:
        score -= 20
        reasons.append('cpu_high')
    if mem and mem >= 90:
        score -= 20
        reasons.append('memory_high')
    if disk and disk >= 92:
        score -= 20
        reasons.append('disk_high')

    error_logs = LogEntry.objects.filter(
        organization=agent.organization,
        agent=agent,
        ts__gte=now - timedelta(minutes=30),
        level=LogEntry.Level.ERROR,
    ).count()
    if error_logs >= 20:
        score -= 20
        reasons.append('error_log_flood')
    elif error_logs >= 5:
        score -= 10
        reasons.append('error_log_burst')

    http_5xx = recent_metrics.filter(name='http.errors.count', labels_json__status_class='5xx').count()
    if http_5xx >= 3:
        score -= 15
        reasons.append('http_5xx_spike')

    return max(0, min(100, int(score))), reasons


def calculate_app_health(app):
    score = 100
    meta = app.metadata_json or {}
    if meta.get('error_rate', 0) > 0.1:
        score -= 20
    if meta.get('latency_p95_ms', 0) > 1000:
        score -= 15
    if meta.get('restarts', 0) > 0:
        score -= 20
    return max(0, min(100, int(score)))
