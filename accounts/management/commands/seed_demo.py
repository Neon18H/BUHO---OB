from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import Organization, User
from agents.models import Agent, AgentEnrollmentToken
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

        orgadmin = User.objects.filter(username='orgadmin').first()

        agents = [
            ('VPS-DEV-01', 'vps-dev-01.local', '10.10.0.11', Agent.Status.ONLINE, timezone.now()),
            ('VPS-QA-01', 'vps-qa-01.local', '10.10.0.21', Agent.Status.DEGRADED, timezone.now() - timedelta(minutes=15)),
            ('VPS-LEGACY-01', 'vps-legacy-01.local', '10.10.0.31', Agent.Status.OFFLINE, timezone.now() - timedelta(days=2)),
        ]
        for name, hostname, ip, status, last_seen in agents:
            Agent.objects.get_or_create(
                organization=org,
                name=name,
                defaults={
                    'hostname': hostname,
                    'ip_address': ip,
                    'os': 'Ubuntu 22.04 LTS' if 'LEGACY' not in name else 'CentOS 7',
                    'version': '1.0.0-demo',
                    'status': status,
                    'last_seen': last_seen,
                },
            )

        if AgentEnrollmentToken.objects.count() < 2:
            AgentEnrollmentToken.objects.get_or_create(
                organization=org,
                token=AgentEnrollmentToken.generate_secure_token(),
                defaults={
                    'expires_at': timezone.now() + timedelta(days=7),
                    'is_used': False,
                    'created_by': orgadmin,
                },
            )
            AgentEnrollmentToken.objects.get_or_create(
                organization=org,
                token=AgentEnrollmentToken.generate_secure_token(),
                defaults={
                    'expires_at': timezone.now() - timedelta(hours=1),
                    'is_used': True,
                    'created_by': orgadmin,
                },
            )

        if AuditLog.objects.count() < 20:
            for idx in range(1, 21):
                AuditLog.objects.create(
                    organization=org,
                    actor=orgadmin,
                    action='VIEW_AGENT' if idx % 2 else 'UPDATE_USER',
                    target_type='Agent' if idx % 2 else 'User',
                    target_id=str(idx),
                    metadata={'demo': True, 'sequence': idx, 'agent': 'VPS-DEV-01' if idx % 2 else None},
                    ip_address='127.0.0.1',
                    user_agent='seed_demo',
                    created_at=timezone.now(),
                )

        self.stdout.write(self.style.SUCCESS('Demo seed completed.'))
        self.stdout.write('Demo credentials (password for all users: BuhoDemo123!)')
        for username, role, org_obj in users:
            org_name = org_obj.name if org_obj else 'All Organizations'
            self.stdout.write(f' - {username} ({role}) | org: {org_name}')
