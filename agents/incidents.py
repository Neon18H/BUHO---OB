from datetime import timedelta

from django.utils import timezone

from .models import Incident, LogEntry, MetricPoint


def upsert_incident(*, org, agent, incident_type, severity, context):
    now = timezone.now()
    incident, created = Incident.objects.get_or_create(
        organization=org,
        agent=agent,
        type=incident_type,
        status=Incident.Status.OPEN,
        defaults={
            'severity': severity,
            'started_at': now,
            'last_seen': now,
            'context_json': context,
        },
    )
    if not created:
        incident.severity = severity
        incident.last_seen = now
        incident.context_json = context
        incident.save(update_fields=['severity', 'last_seen', 'context_json'])


def evaluate_metric_incidents(org, agent):
    recent_cpu = list(
        MetricPoint.objects.filter(
            organization=org,
            agent=agent,
            name='cpu.percent',
        )
        .order_by('-ts')
        .values_list('value', flat=True)[:3]
    )
    if len(recent_cpu) == 3 and all(val > 90 for val in recent_cpu):
        upsert_incident(
            org=org,
            agent=agent,
            incident_type=Incident.Type.CPU_SPIKE,
            severity=Incident.Severity.HIGH,
            context={'samples': recent_cpu},
        )

    disk = (
        MetricPoint.objects.filter(
            organization=org,
            agent=agent,
            name='disk.root.used_percent',
        )
        .order_by('-ts')
        .first()
    )
    if disk and disk.value > 90:
        upsert_incident(
            org=org,
            agent=agent,
            incident_type=Incident.Type.DISK_CRITICAL,
            severity=Incident.Severity.CRITICAL,
            context={'value': disk.value},
        )


def evaluate_log_incidents(org, agent):
    since = timezone.now() - timedelta(minutes=5)
    errors = LogEntry.objects.filter(
        organization=org,
        agent=agent,
        level=LogEntry.Level.ERROR,
        ts__gte=since,
    ).count()
    if errors > 20:
        upsert_incident(
            org=org,
            agent=agent,
            incident_type=Incident.Type.LOG_ERROR_FLOOD,
            severity=Incident.Severity.HIGH,
            context={'errors_5m': errors},
        )
