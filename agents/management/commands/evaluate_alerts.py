from django.conf import settings
from django.core.management.base import BaseCommand

from agents.incidents import evaluate_offline_incidents
from accounts.models import Organization


class Command(BaseCommand):
    help = 'Evaluate offline incidents for all organizations.'

    def handle(self, *args, **options):
        offline_seconds = getattr(settings, 'AGENT_OFFLINE_SECONDS', 90)
        for org in Organization.objects.all():
            evaluate_offline_incidents(org, offline_seconds=offline_seconds)
        self.stdout.write(self.style.SUCCESS('Alert evaluation complete.'))
