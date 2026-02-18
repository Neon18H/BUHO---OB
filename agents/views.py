from textwrap import dedent
from datetime import timedelta

from django.contrib import messages
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from audit.utils import create_audit_log
from ui.permissions import RoleRequiredUIMixin

from .forms import TokenCreateForm
from .models import Agent, AgentEnrollmentToken


AGENT_REQUIREMENTS = "requests\npsutil\n"


def build_agent_py():
    return dedent(
        """
        import argparse
        import json
        import os
        import platform
        import socket
        import time
        from datetime import datetime, timezone
        from pathlib import Path
        from urllib.error import URLError
        from urllib.request import Request, urlopen

        try:
            import psutil
        except Exception:
            psutil = None

        try:
            import requests
        except Exception:
            requests = None

        VERSION = "0.2.0"

        def utc_now():
            return datetime.now(timezone.utc).isoformat()

        def load_config(path):
            p = Path(path)
            if not p.exists():
                return {}
            return json.loads(p.read_text(encoding="utf-8"))

        def save_config(path, cfg):
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

        def post_json(url, payload, headers=None, timeout=10):
            headers = headers or {}
            if requests:
                r = requests.post(url, json=payload, headers=headers, timeout=timeout)
                return r.status_code, r.json() if r.content else {}
            data = json.dumps(payload).encode("utf-8")
            req = Request(url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST")
            try:
                with urlopen(req, timeout=timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    return resp.status, json.loads(raw) if raw else {}
            except URLError as exc:
                raise RuntimeError(str(exc))

        def get_ip_address():
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

        def get_disk_target():
            if os.name == "nt":
                system_drive = os.environ.get("SystemDrive", "C:")
                return os.path.join(system_drive, "\\\\")
            return "/"

        def collect_metrics():
            if not psutil:
                return [{"name": "cpu.percent", "value": 0, "unit": "%"}]
            disk_target = get_disk_target()
            d = psutil.disk_usage(disk_target)
            m = psutil.virtual_memory()
            n = psutil.net_io_counters()
            rows = [
                {"name": "cpu.percent", "value": psutil.cpu_percent(interval=0.1), "unit": "%"},
                {"name": "mem.percent", "value": m.percent, "unit": "%"},
                {"name": "disk.root.used_percent", "value": d.percent, "unit": "%"},
                {"name": "net.bytes_sent", "value": n.bytes_sent, "unit": "bytes"},
                {"name": "net.bytes_recv", "value": n.bytes_recv, "unit": "bytes"},
                {"name": "uptime.seconds", "value": time.time() - psutil.boot_time(), "unit": "seconds"},
            ]
            if hasattr(os, "getloadavg"):
                rows.append({"name": "load.1m", "value": os.getloadavg()[0], "unit": "load"})
            return rows

        def collect_processes(limit=25):
            if not psutil:
                return []
            rows = []
            for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent", "memory_percent"]):
                try:
                    rows.append(
                        {
                            "pid": proc.info.get("pid", 0),
                            "name": (proc.info.get("name") or "unknown")[:255],
                            "cpu": float(proc.info.get("cpu_percent") or 0),
                            "mem": float(proc.info.get("memory_percent") or 0),
                            "user": (proc.info.get("username") or "")[:255],
                            "cmdline": " ".join(proc.info.get("cmdline") or [])[:500],
                        }
                    )
                except Exception:
                    continue
            rows.sort(key=lambda item: (item["cpu"], item["mem"]), reverse=True)
            return rows[:limit]

        def collect_logs(log_file):
            p = Path(log_file)
            if not p.exists():
                return []
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()[-10:]
            return [{"ts": utc_now(), "level": "INFO", "source": "agent", "message": line, "fields": {}} for line in lines]

        def enroll(config_path):
            cfg = load_config(config_path)
            if cfg.get("agent_id") and cfg.get("agent_key"):
                return cfg
            payload = {
                "token": cfg["token"],
                "hostname": socket.gethostname(),
                "ip_address": get_ip_address(),
                "os": platform.platform(),
                "arch": platform.machine(),
                "version": VERSION,
                "name": socket.gethostname(),
            }
            status_code, data = post_json(f"{cfg['server_url']}/api/agents/enroll", payload)
            if status_code != 200:
                raise RuntimeError(f"enroll failed: {status_code}")
            cfg["agent_id"] = data["agent_id"]
            cfg["agent_key"] = data["agent_key"]
            save_config(config_path, cfg)
            return cfg

        def run_loop(config_path, once=False):
            cfg = load_config(config_path)
            cfg = enroll(config_path)
            headers = {"X-Buho-Agent-Id": str(cfg["agent_id"]), "X-Buho-Agent-Key": cfg["agent_key"]}
            heartbeat_interval = int(cfg.get("heartbeat_interval", 15))
            metrics_interval = int(cfg.get("metrics_interval", 10))
            processes_interval = int(cfg.get("processes_interval", 15))
            last_heartbeat = 0
            last_metrics = 0
            last_processes = 0
            backoff = 2

            while True:
                now = time.time()
                try:
                    if now - last_heartbeat >= heartbeat_interval:
                        post_json(f"{cfg['server_url']}/api/agents/heartbeat", {"status": "ONLINE", "metadata": {"agent_version": VERSION}}, headers)
                        last_heartbeat = now
                    if now - last_metrics >= metrics_interval:
                        post_json(f"{cfg['server_url']}/api/ingest/metrics", {"ts": utc_now(), "metrics": collect_metrics()}, headers)
                        post_json(f"{cfg['server_url']}/api/ingest/logs", {"logs": collect_logs(cfg.get("log_file", "buho-agent.log"))}, headers)
                        last_metrics = now
                    if now - last_processes >= processes_interval:
                        post_json(f"{cfg['server_url']}/api/ingest/processes", {"ts": utc_now(), "processes": collect_processes()}, headers)
                        last_processes = now
                    backoff = 2
                    if once:
                        return
                    time.sleep(1)
                except Exception as exc:
                    Path(cfg.get("log_file", "buho-agent.log")).parent.mkdir(parents=True, exist_ok=True)
                    with open(cfg.get("log_file", "buho-agent.log"), "a", encoding="utf-8") as handle:
                        handle.write(f"{utc_now()} loop-error {exc}\\n")
                    if once:
                        raise
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)

        def main():
            parser = argparse.ArgumentParser(description="Buho Agent")
            parser.add_argument("--config", required=True)
            parser.add_argument("--enroll", action="store_true")
            parser.add_argument("--run", action="store_true")
            parser.add_argument("--once", action="store_true")
            args = parser.parse_args()
            if args.enroll:
                enroll(args.config)
                return
            if args.run or args.once:
                run_loop(args.config, once=args.once)
                return
            parser.error("Use --enroll, --run or --once")

        if __name__ == "__main__":
            main()
        """
    ).strip() + "\n"


def build_windows_installer(server_url: str, token: str):
    return dedent(
        f"""
        $ErrorActionPreference = "Stop"
        $BuhoUrl = "{server_url}"
        $Token = "{token}"
        $InstallRoot = "C:\\ProgramData\\BuhoAgent"
        $ConfigPath = Join-Path $InstallRoot "config.json"
        $LogPath = Join-Path $InstallRoot "buho-agent.log"
        $AgentPyPath = Join-Path $InstallRoot "agent.py"
        $ReqPath = Join-Path $InstallRoot "requirements.txt"

        function Write-Step($message) {{ Write-Host "[BuhoAgent] $message" -ForegroundColor Cyan }}
        function Write-ErrorStep($message) {{ Write-Host "[BuhoAgent] ERROR: $message" -ForegroundColor Red }}

        if ($PSVersionTable.PSVersion.Major -lt 5) {{ Write-Host "PowerShell 5+ requerido." -ForegroundColor Red; exit 1 }}
        if (-not (Get-Command python -ErrorAction SilentlyContinue)) {{
            Write-Host "Python 3 no encontrado en PATH. Instálalo desde https://www.python.org/downloads/windows/." -ForegroundColor Yellow
            exit 1
        }}

        New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
        Write-Step "Descargando agent.py y requirements.txt"
        Invoke-WebRequest -Uri "$BuhoUrl/agents/download/agent.py" -OutFile $AgentPyPath
        Invoke-WebRequest -Uri "$BuhoUrl/agents/download/requirements.txt" -OutFile $ReqPath

        $config = @{{
            server_url = $BuhoUrl
            token = $Token
            heartbeat_interval = 15
            metrics_interval = 10
            processes_interval = 15
            log_file = $LogPath
        }}
        $config | ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8

        Write-Step "Creando entorno virtual"
        python -m venv (Join-Path $InstallRoot "venv")
        $PyExe = Join-Path $InstallRoot "venv\\Scripts\\python.exe"
        & $PyExe -m pip install --disable-pip-version-check -r $ReqPath

        Write-Step "Validando sintaxis de agent.py"
        $compileOutput = & $PyExe -m py_compile $AgentPyPath 2>&1
        if ($LASTEXITCODE -ne 0) {{
            Write-ErrorStep "agent.py tiene error de sintaxis"
            $compileOutput | ForEach-Object {{ Write-Host $_ -ForegroundColor Red }}
            exit 1
        }}

        Write-Step "Ejecutando enroll"
        & $PyExe $AgentPyPath --enroll --config $ConfigPath
        if ($LASTEXITCODE -ne 0) {{
            Write-ErrorStep "Enroll falló. No se creó tarea programada."
            exit 1
        }}

        $taskAction = New-ScheduledTaskAction -Execute $PyExe -Argument "`"$InstallRoot\\agent.py`" --run --config `"$ConfigPath`""
        $triggerStartup = New-ScheduledTaskTrigger -AtStartup
        $triggerLogin = New-ScheduledTaskTrigger -AtLogOn

        try {{
            Write-Step "Creando tarea programada global BuhoAgent"
            Register-ScheduledTask -TaskName "BuhoAgent" -Action $taskAction -Trigger @($triggerStartup, $triggerLogin) -RunLevel Highest -Force | Out-Null
        }} catch {{
            Write-Host "No se pudo crear tarea global (sin admin). Intentando tarea en contexto de usuario..." -ForegroundColor Yellow
            Register-ScheduledTask -TaskName "BuhoAgent" -Action $taskAction -Trigger @($triggerLogin) -Force | Out-Null
        }}

        try {{
            Start-ScheduledTask -TaskName "BuhoAgent" | Out-Null
        }} catch {{
            Write-ErrorStep "No se pudo iniciar la tarea programada BuhoAgent."
            Write-Host $_ -ForegroundColor Red
            exit 1
        }}

        Write-Host "[BuhoAgent] Instalación completa ✅" -ForegroundColor Green
        Write-Host "[BuhoAgent] Logs: C:\\ProgramData\\BuhoAgent\\buho-agent.log" -ForegroundColor Green
        Write-Host "[BuhoAgent] Verifica ONLINE en: $BuhoUrl/agents/overview" -ForegroundColor Green
        """
    ).strip() + "\n"


class AgentOrganizationMixin:
    def scoped_organization(self, request):
        return request.user.organization

    def scoped_agents(self, request):
        org = self.scoped_organization(request)
        qs = Agent.objects.select_related('organization')
        return qs.filter(organization=org) if org else qs.none()

    def scoped_tokens(self, request):
        org = self.scoped_organization(request)
        qs = AgentEnrollmentToken.objects.select_related('organization', 'created_by')
        return qs.filter(organization=org) if org else qs.none()


class AgentsOverviewView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True

    def get(self, request):
        agents = self.scoped_agents(request)
        cutoff = timezone.now() - timedelta(seconds=90)
        agents.filter(last_seen__lt=cutoff).exclude(status=Agent.Status.OFFLINE).update(status=Agent.Status.OFFLINE)
        agents.filter(last_seen__gte=cutoff).exclude(status=Agent.Status.ONLINE).update(status=Agent.Status.ONLINE)
        create_audit_log(request=request, actor=request.user, action='VIEW_AGENT', target_type='AgentList', metadata={'count': agents.count()})
        return render(
            request,
            'agents/overview.html',
            {
                'agents': agents,
                'can_manage_tokens': request.user.role in {'SUPERADMIN', 'ORG_ADMIN'},
                'online_count': agents.filter(status=Agent.Status.ONLINE).count(),
                'offline_count': agents.filter(status=Agent.Status.OFFLINE).count(),
                'degraded_count': agents.filter(status=Agent.Status.DEGRADED).count(),
            },
        )


class AgentDetailView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True

    def get(self, request, agent_id):
        agent = get_object_or_404(self.scoped_agents(request), id=agent_id)
        create_audit_log(request=request, actor=request.user, action='VIEW_AGENT', target_type='Agent', target_id=str(agent.id))
        return render(request, 'agents/detail.html', {'agent': agent, 'heartbeats': agent.heartbeats.all()[:20]})


class AgentsInstallView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True

    def get(self, request):
        latest_token = self.scoped_tokens(request).first()
        server_url = request.build_absolute_uri('/').rstrip('/')
        loopback_hosts = {'127.0.0.1', 'localhost'}
        show_remote_hint = request.get_host().split(':')[0].lower() in loopback_hosts
        return render(
            request,
            'agents/install.html',
            {
                'form': TokenCreateForm(),
                'latest_token': latest_token,
                'server_url': server_url,
                'show_remote_hint': show_remote_hint,
                'can_manage_tokens': request.user.role in {'SUPERADMIN', 'ORG_ADMIN'},
            },
        )


class TokensView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}
    permission_redirect_url = 'agents:install'
    require_organization = True

    def get(self, request):
        tokens = self.scoped_tokens(request)
        create_audit_log(request=request, actor=request.user, action='VIEW_TOKENS', target_type='AgentEnrollmentToken', metadata={'count': tokens.count()})
        return render(request, 'agents/tokens.html', {'tokens': tokens, 'form': TokenCreateForm()})


class TokenCreateView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}
    permission_redirect_url = 'agents:install'
    require_organization = True

    def post(self, request):
        form = TokenCreateForm(request.POST)
        if not form.is_valid():
            messages.error(request, 'Invalid token request.')
            return redirect(request.META.get('HTTP_REFERER', 'agents:tokens'))

        org = self.scoped_organization(request)
        if org is None:
            messages.error(request, 'No tienes organización asignada.')
            return redirect('agents:tokens')

        token = AgentEnrollmentToken.objects.create(
            organization=org,
            token=AgentEnrollmentToken.generate_secure_token(),
            expires_at=form.get_expires_at(),
            created_by=request.user,
            server_name_optional=form.cleaned_data['server_name_optional'],
            tags_json=form.get_tags(),
            allow_multi_use=form.cleaned_data['allow_multi_use'],
        )
        create_audit_log(
            request=request,
            actor=request.user,
            action='CREATE_TOKEN',
            target_type='AgentEnrollmentToken',
            target_id=str(token.id),
            organization=org,
            metadata={'token_preview': token.masked_token, 'expires_at': token.expires_at.isoformat()},
        )
        messages.success(request, 'Installation token created.')
        return redirect(request.META.get('HTTP_REFERER', 'agents:tokens'))


class TokenRevokeView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}
    permission_redirect_url = 'agents:install'
    require_organization = True

    def post(self, request, token_id):
        token = get_object_or_404(self.scoped_tokens(request), id=token_id)
        token.is_revoked = True
        token.save(update_fields=['is_revoked'])
        create_audit_log(
            request=request,
            actor=request.user,
            action='REVOKE_TOKEN',
            target_type='AgentEnrollmentToken',
            target_id=str(token.id),
            organization=token.organization,
            metadata={'token_preview': token.masked_token},
        )
        messages.success(request, 'Token revoked.')
        return redirect('agents:tokens')


class AgentDownloadLinuxView(View):
    def get(self, request):
        token = request.GET.get('token', '')
        if not token:
            return HttpResponseBadRequest('token required')
        server_url = request.build_absolute_uri('/').rstrip('/')
        script = dedent(
            f"""#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="$HOME/.buho-agent"
mkdir -p "$INSTALL_DIR"
curl -fsSL {server_url}/agents/download/agent.py -o "$INSTALL_DIR/agent.py"
cat > "$INSTALL_DIR/config.json" <<EOF
{{"server_url":"{server_url}","token":"{token}","heartbeat_interval":15,"metrics_interval":10,"processes_interval":15,"log_file":"$INSTALL_DIR/buho-agent.log"}}
EOF
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -r <(curl -fsSL {server_url}/agents/download/requirements.txt) || true
nohup "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --run --config "$INSTALL_DIR/config.json" >/dev/null 2>&1 &
"""
        )
        response = HttpResponse(script, content_type='text/x-shellscript')
        response['Content-Disposition'] = 'attachment; filename="buho-agent-linux.sh"'
        return response


class AgentDownloadWindowsView(View):
    def get(self, request):
        token = request.GET.get('token', '')
        if not token:
            return HttpResponseBadRequest('token required')
        server_url = request.build_absolute_uri('/').rstrip('/')
        response = HttpResponse(build_windows_installer(server_url, token), content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="buho-agent-windows.ps1"'
        return response


class AgentDownloadAgentPyView(View):
    def get(self, request):
        response = HttpResponse(build_agent_py(), content_type='text/x-python')
        response['Content-Disposition'] = 'attachment; filename="agent.py"'
        return response


class AgentDownloadRequirementsView(View):
    def get(self, request):
        response = HttpResponse(AGENT_REQUIREMENTS, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="requirements.txt"'
        return response
