from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts.models import Organization
from agents.models import AgentEnrollmentToken
from agents.views import build_agent_py, build_windows_installer

User = get_user_model()


class AgentDownloadScriptTests(TestCase):
    def test_agent_py_windows_disk_target_uses_system_drive(self):
        script = build_agent_py()

        self.assertIn('system_drive = os.environ.get("SystemDrive", "C:")', script)
        self.assertIn('disk_target = system_drive + "\\" if os.name == "nt" else "/"', script)
        self.assertNotIn('disk_target = "C:\\" if os.name == "nt" else "/"', script)

    def test_windows_installer_fails_fast_before_scheduled_task(self):
        script = build_windows_installer('http://buho.example', 'tok123')

        self.assertIn('& $PyExe -m py_compile $AgentPyPath', script)
        self.assertIn('Write-ErrorStep "agent.py tiene error de sintaxis"', script)
        self.assertIn('Write-ErrorStep "Enroll falló. No se creó tarea programada."', script)
        self.assertIn('[BuhoAgent] Instalación completa ✅', script)

        compile_idx = script.index('& $PyExe -m py_compile $AgentPyPath')
        enroll_idx = script.index('& $PyExe $AgentPyPath --enroll --config $ConfigPath')
        task_idx = script.index('Register-ScheduledTask -TaskName "BuhoAgent"')
        self.assertLess(compile_idx, task_idx)
        self.assertLess(enroll_idx, task_idx)


class AgentInstallHintTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name='Org 1')
        self.user = User.objects.create_user(
            username='viewer-user',
            password='pass1234',
            role='VIEWER',
            organization=self.organization,
        )

    def test_install_page_shows_remote_hint_on_loopback(self):
        token = AgentEnrollmentToken.objects.create(
            organization=self.organization,
            token=AgentEnrollmentToken.generate_secure_token(),
            expires_at=timezone.now() + timedelta(hours=24),
            created_by=self.user,
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse('agents:install'), HTTP_HOST='127.0.0.1:8000')

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'cambia <code>127.0.0.1</code> por la IP/DNS del servidor Buho')
        self.assertContains(response, token.token)
