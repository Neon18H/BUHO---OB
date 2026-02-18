from django.core.management.base import BaseCommand

from accounts.models import Organization, User


class Command(BaseCommand):
    help = 'Optional local seed: create a single organization with admin and basic users.'

    def handle(self, *args, **options):
        org, _ = Organization.objects.get_or_create(name='DemoOrg', defaults={'plan': Organization.Plan.PRO})
        users = [
            ('superadmin', 'SUPERADMIN', org),
            ('orgadmin', 'ORG_ADMIN', org),
            ('analyst', 'ANALYST', org),
            ('viewer', 'VIEWER', org),
        ]
        for username, role, organization in users:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': f'{username}@buho.local',
                    'role': role,
                    'organization': organization,
                    'is_staff': role == 'SUPERADMIN',
                    'is_superuser': False,
                },
            )
            if created:
                user.set_password('BuhoDemo123!')
                user.save()
        self.stdout.write(self.style.SUCCESS('Users seeded. Password for all: BuhoDemo123!'))
