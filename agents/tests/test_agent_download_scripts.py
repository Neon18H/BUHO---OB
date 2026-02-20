import py_compile
import tempfile
from datetime import timedelta
from pathlib import Path

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
        self.assertIn('def get_disk_target():', script)
        self.assertIn('return os.path.join(system_drive, "\\\\")', script)
        self.assertIn('disk_target = get_disk_target()', script)
        self.assertIn('return json.loads(p.read_text(encoding="utf-8-sig"))', script)
        self.assertNotIn('disk_target = "C:\\" if os.name == "nt" else "/"', script)

    def test_generated_agent_py_compiles(self):
        script = build_agent_py()

        with tempfile.TemporaryDirectory() as tmpdir:
            agent_path = Path(tmpdir) / 'agent.py'
            agent_path.write_text(script, encoding='utf-8')
            py_compile.compile(str(agent_path), doraise=True)

    def test_generated_agent_py_has_no_leading_blank_or_global_indent(self):
        script = build_agent_py()

        self.assertTrue(script.startswith('#!/usr/bin/env python3\n'))
        self.assertNotEqual(script[0], '\n')
        self.assertEqual(script[0], '#')

    def test_generated_agent_logs_startup_identity_and_global_exception(self):
        script = build_agent_py()

        self.assertIn('def log_startup(cfg):', script)
        self.assertIn('username=', script)
        self.assertIn('is_system=', script)
        self.assertIn('def install_global_excepthook(log_file):', script)
        self.assertIn('unhandled exception', script)

    def test_download_endpoint_returns_valid_python(self):
        response = self.client.get(reverse('agents:download_agent_py'))

        self.assertEqual(response.status_code, 200)
        script = response.content.decode('utf-8')
        compile(script, 'agent.py', 'exec')

    def test_windows_installer_fails_fast_before_scheduled_task(self):
        script = build_windows_installer('http://buho.example', 'tok123')

        self.assertIn('& $PyExe -m py_compile $AgentPyPath', script)
        self.assertIn('Write-ErrorStep "agent.py tiene error de sintaxis"', script)
        self.assertIn('Write-ErrorStep "Enroll falló. No se creó tarea programada."', script)
        self.assertIn('Write-RepairInstructions', script)
        self.assertIn('[System.IO.File]::WriteAllText($ConfigPath, $cfgJson, (New-Object System.Text.UTF8Encoding($false)))', script)
        config_validate_cmd = "& $PyExe -c \"import json; import pathlib; p=pathlib.Path(r'$ConfigPath'); json.loads(p.read_text(encoding='utf-8-sig')); print('config json OK')\""
        self.assertIn(config_validate_cmd, script)

        compile_idx = script.index('& $PyExe -m py_compile $AgentPyPath')
        enroll_idx = script.index('& $PyExe $AgentPyPath --enroll --config $ConfigPath')
        validate_idx = script.index(config_validate_cmd)
        task_idx = script.index('& schtasks.exe @createArgs')
        self.assertLess(validate_idx, enroll_idx)
        self.assertLess(compile_idx, task_idx)
        self.assertLess(enroll_idx, task_idx)

    def test_windows_installer_uses_schtasks_system_onstart_and_runner_logging(self):
        script = build_windows_installer('http://buho.example', 'tok123')

        self.assertIn("'/SC', 'ONSTART'", script)
        self.assertIn("'/RU', 'SYSTEM'", script)
        self.assertIn("'/RL', 'HIGHEST'", script)
        self.assertIn('$TaskCommand = \'cmd.exe /c "C:\\ProgramData\\BuhoAgent\\run-agent.cmd"\'', script)
        self.assertIn('$RunnerCmdPath = Join-Path $InstallRoot "run-agent.cmd"', script)
        self.assertIn('chcp 65001 >nul', script)
        self.assertIn('cd /d C:\\ProgramData\\BuhoAgent', script)
        self.assertIn('>> "$LogPath" 2>&1', script)
        self.assertIn('goto loop', script)
        self.assertIn('Creando tarea programada BuhoAgent (SYSTEM/ONSTART)', script)
        self.assertIn('Start-ScheduledTask -TaskName "BuhoAgent"', script)
        self.assertIn('Get-CimInstance Win32_Process', script)
        self.assertIn('schtasks.exe /Query /TN "BuhoAgent" /V /FO LIST', script)
        self.assertIn('install.log', script)
        self.assertIn('run-manual.ps1', script)
        self.assertIn('No se pudo crear la tarea programada BuhoAgent.', script)
        self.assertNotIn("'/SC', 'ONLOGON'", script)


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

    def test_overview_has_windows_troubleshooting_block(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse('agents:overview'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'View local logs instructions')
        self.assertContains(response, 'schtasks /Query /TN "BuhoAgent" /V /FO LIST')
        self.assertContains(response, 'run --config "C:\\ProgramData\\BuhoAgent\\config.json"')
