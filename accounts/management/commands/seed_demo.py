from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import Organization, User
from audit.models import AuditLog


class Command(BaseCommand):
    help = 'Seeds demo data for Buho dashboard MVP.'

    def handle(self, *args, **options):
        org, _ = Organization.objects.get_or_create(name='DemoOrg', defaults={'plan': Organization.Plan.PRO})

        users = [
            ('superadmin', 'SUPERADMIN', None),
            ('orgadmin', 'ORG_ADMIN', org),
            ('analyst', 'ANALYST', org),
            ('viewer', 'VIEWER', org),
        ]

        created_users = []
        for username, role, organization in users:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': f'{username}@buho.local',
                    'role': role,
                    'organization': organization,
                    'is_staff': role == 'SUPERADMIN',
                    'is_superuser': role == 'SUPERADMIN',
                },
            )
            if created:
                user.set_password('BuhoDemo123!')
                user.save()
                created_users.append(user)

        if AuditLog.objects.count() < 15:
            actor = User.objects.filter(username='orgadmin').first()
            for idx in range(1, 16):
                AuditLog.objects.create(
                    organization=org,
                    actor=actor,
                    action='VIEW' if idx % 2 else 'UPDATE',
                    target_type='Dashboard',
                    target_id=str(idx),
                    metadata={'demo': True, 'sequence': idx},
                    ip_address='127.0.0.1',
                    user_agent='seed_demo',
                    created_at=timezone.now(),
                )

        self.stdout.write(self.style.SUCCESS('Demo seed completed.'))
        self.stdout.write('Demo credentials (password for all users: BuhoDemo123!)')
        for username, role, org_obj in users:
            org_name = org_obj.name if org_obj else 'All Organizations'
            self.stdout.write(f' - {username} ({role}) | org: {org_name}')
