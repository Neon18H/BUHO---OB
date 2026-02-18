from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from agents.models import AgentHeartbeat, LogEntry, MetricPoint, ProcessSample


class Command(BaseCommand):
    help = 'Delete telemetry older than RETENTION_DAYS.'

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=getattr(settings, 'RETENTION_DAYS', 7))
        metrics = MetricPoint.objects.filter(ts__lt=cutoff).delete()[0]
        proc = ProcessSample.objects.filter(ts__lt=cutoff).delete()[0]
        logs = LogEntry.objects.filter(ts__lt=cutoff).delete()[0]
        hb = AgentHeartbeat.objects.filter(ts__lt=cutoff).delete()[0]
        self.stdout.write(self.style.SUCCESS(f'cleanup_old_data complete (metrics={metrics}, processes={proc}, logs={logs}, heartbeats={hb})'))
