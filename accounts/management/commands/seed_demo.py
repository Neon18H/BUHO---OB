from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Backward-compatible seed command (users/org only).'

    def handle(self, *args, **options):
        call_command('seed_users')
        self.stdout.write(self.style.WARNING('seed_demo now seeds users/org only (no fake agents or telemetry).'))
