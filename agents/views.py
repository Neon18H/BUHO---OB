import logging
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
from .models import Agent, AgentEnrollmentToken, DetectedApp


AGENT_REQUIREMENTS = "requests\npsutil\n"
logger = logging.getLogger(__name__)


def build_agent_py():
    return (
        """
        #!/usr/bin/env python3
        import argparse
        import json
        import os
        import platform
        import re
        import socket
        import subprocess
        import time
        from collections import Counter, defaultdict
        from datetime import datetime, timezone
        from pathlib import Path

        import psutil
        import requests

        VERSION = "0.3.0"
        SECRET_PATTERNS = [r"(?i)(authorization:|bearer\\s+)[^\\s]+", r"(?i)(password|token|api[_-]?key)=([^&\\s]+)"]

        def utc_now():
            return datetime.now(timezone.utc).isoformat()

        def redact(text):
            value = str(text or "")
            for pattern in SECRET_PATTERNS:
                value = re.sub(pattern, "[REDACTED]", value)
            return value

        def load_json(path, default):
            p = Path(path)
            if not p.exists():
                return default
            try:
                return json.loads(p.read_text(encoding="utf-8-sig"))
            except Exception:
                return default

        def save_json(path, payload):
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        def post_json(url, payload, headers=None, timeout=5):
            headers = headers or {}
            response = requests.post(url, json=payload, headers=headers, timeout=timeout)
            return response.status_code, response.json() if response.content else {}

        def get_disk_target():
            if os.name == "nt":
                system_drive = os.environ.get("SystemDrive", "C:")
                return os.path.join(system_drive, "\\\\")
            return "/"

        def enqueue_spool(path, event):
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event) + "\\n")
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()[-5000:]
            while len("\\n".join(lines).encode("utf-8")) > 50 * 1024 * 1024 and lines:
                lines = lines[1:]
            p.write_text("\\n".join(lines) + ("\\n" if lines else ""), encoding="utf-8")

        def flush_spool(cfg, headers):
            p = Path(cfg["spool_file"])
            if not p.exists():
                return
            keep = []
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                try:
                    status_code, _ = post_json(cfg["server_url"] + item["path"], item["payload"], headers=headers, timeout=5)
                    if status_code >= 300:
                        keep.append(line)
                except Exception:
                    keep.append(line)
            p.write_text("\\n".join(keep) + ("\\n" if keep else ""), encoding="utf-8")

        def post_with_retry(cfg, headers, path, payload):
            for wait in [1, 2, 5, 10, 20, 30, 45, 60]:
                try:
                    status_code, _ = post_json(cfg["server_url"] + path, payload, headers=headers, timeout=5)
                    if status_code < 300:
                        return True
                except Exception:
                    pass
                time.sleep(wait)
            enqueue_spool(cfg["spool_file"], {"path": path, "payload": payload})
            return False

        def collect_metrics():
            disk_target = get_disk_target()
            vm = psutil.virtual_memory()
            net = psutil.net_io_counters()
            rows = [
                {"name": "cpu.percent", "value": psutil.cpu_percent(interval=None), "unit": "%"},
                {"name": "mem.percent", "value": vm.percent, "unit": "%"},
                {"name": "mem.used", "value": vm.used, "unit": "bytes"},
                {"name": "mem.available", "value": vm.available, "unit": "bytes"},
                {"name": "net.bytes_sent", "value": net.bytes_sent, "unit": "bytes"},
                {"name": "net.bytes_recv", "value": net.bytes_recv, "unit": "bytes"},
                {"name": "uptime.seconds", "value": time.time() - psutil.boot_time(), "unit": "seconds"},
            ]
            try:
                rows.append({"name": "swap.percent", "value": psutil.swap_memory().percent, "unit": "%"})
            except Exception:
                pass
            try:
                rows.append({"name": "disk.root.used_percent", "value": psutil.disk_usage(disk_target).percent, "unit": "%"})
            except Exception:
                pass
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    rows.append({"name": "disk.used_percent", "value": usage.percent, "unit": "%", "labels": {"partition": part.device, "mount": part.mountpoint}})
                except Exception:
                    continue
            if hasattr(os, "getloadavg"):
                l1, l5, l15 = os.getloadavg()
                rows.extend([
                    {"name": "load.1m", "value": l1, "unit": "load"},
                    {"name": "load.5m", "value": l5, "unit": "load"},
                    {"name": "load.15m", "value": l15, "unit": "load"},
                ])
            return rows

        def collect_processes_and_apps():
            listen = defaultdict(list)
            apps = []
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if conn.status == psutil.CONN_LISTEN and conn.pid:
                        listen[conn.pid].append(conn.laddr.port)
            except Exception:
                pass
            proc_rows = []
            for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent", "memory_percent"]):
                try:
                    cmdline = redact(" ".join(proc.info.get("cmdline") or []))[:500]
                    name = (proc.info.get("name") or "unknown")[:255]
                    proc_rows.append({"pid": proc.info.get("pid", 0), "name": name, "cpu": float(proc.info.get("cpu_percent") or 0), "mem": float(proc.info.get("memory_percent") or 0), "user": (proc.info.get("username") or "")[:255], "cmdline": cmdline})
                    lowered = f"{name} {cmdline}".lower()
                    for hint, kind in {"gunicorn": "python-app", "uvicorn": "python-app", "node": "node", "java": "java", "dotnet": ".net", "nginx": "nginx", "apache": "apache", "postgres": "database", "redis": "cache"}.items():
                        if hint in lowered:
                            apps.append({"name": name[:120], "kind": kind, "pid": proc.info.get("pid"), "ports": sorted(set(listen.get(proc.info.get("pid"), []))), "metadata": {"cmdline": cmdline}})
                            break
                except Exception:
                    continue
            proc_rows.sort(key=lambda item: (item["cpu"], item["mem"]), reverse=True)
            return proc_rows[:50], apps[:100]

        def collect_services():
            rows = []
            if os.name == "nt" and hasattr(psutil, "win_service_iter"):
                for svc in psutil.win_service_iter():
                    try:
                        data = svc.as_dict(); rows.append({"name": data.get("name"), "status": data.get("status")})
                    except Exception:
                        continue
            else:
                try:
                    output = subprocess.check_output(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"], text=True, stderr=subprocess.DEVNULL)
                    for line in output.splitlines():
                        if ".service" in line:
                            rows.append({"name": line.split()[0], "status": "running"})
                except Exception:
                    pass
            return rows[:200]

        def parse_http_logs(path, state):
            p = Path(path)
            if not p.exists():
                return []
            key = f"http::{path}"
            offset = state.get(key, 0)
            counts = Counter()
            with p.open("r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(offset)
                for line in handle.readlines()[-5000:]:
                    match = re.search(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)[^"]*"\s+(\d{3})', line)
                    if not match:
                        continue
                    method, endpoint, status_code = match.groups()
                    status_class = status_code[0] + "xx"
                    endpoint = endpoint[:120]
                    counts[(method, endpoint, status_class)] += 1
                state[key] = handle.tell()
            points = []
            for (method, endpoint, status_class), value in counts.items():
                points.append({"name": "http.requests.count", "value": value, "unit": "count", "labels": {"method": method, "endpoint": endpoint, "status_class": status_class}})
                if status_class in ("4xx", "5xx"):
                    points.append({"name": "http.errors.count", "value": value, "unit": "count", "labels": {"method": method, "endpoint": endpoint, "status_class": status_class}})
            return points

        def collect_logs(cfg, state):
            output = []
            for source in cfg.get("logs_sources", []):
                if source.get("type") != "file":
                    continue
                p = Path(source.get("path", ""))
                if not p.exists():
                    continue
                key = f"file::{p}"
                offset = state.get(key, 0)
                with p.open("r", encoding="utf-8", errors="ignore") as handle:
                    handle.seek(offset)
                    for line in handle.readlines()[-200:]:
                        msg = redact(line.strip())
                        if msg:
                            level = "ERROR" if "error" in msg.lower() else "INFO"
                            output.append({"ts": utc_now(), "level": level, "source": source.get("name") or p.name, "message": msg, "fields": {}})
                    state[key] = handle.tell()
            return output[:200]

        def enroll(config_path):
            cfg = load_json(config_path, {})
            if cfg.get("agent_id") and cfg.get("agent_key"):
                return cfg
            payload = {
                "token": cfg["token"],
                "hostname": socket.gethostname(),
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "os": platform.platform(),
                "arch": platform.machine(),
                "version": VERSION,
                "name": socket.gethostname(),
            }
            status_code, data = post_json(cfg["server_url"] + "/api/agents/enroll", payload)
            if status_code != 200:
                raise RuntimeError(f"enroll failed: {status_code}")
            cfg["agent_id"] = data["agent_id"]
            cfg["agent_key"] = data["agent_key"]
            cfg.setdefault("spool_file", str(Path(config_path).with_name("spool.jsonl")))
            save_json(config_path, cfg)
            return cfg

        def run_loop(config_path, once=False):
            cfg = enroll(config_path)
            cfg.setdefault("heartbeat_interval", 15)
            cfg.setdefault("metrics_interval", 15)
            cfg.setdefault("processes_interval", 30)
            cfg.setdefault("logs_interval", 15)
            cfg.setdefault("logs_sources", [{"type": "file", "path": cfg.get("log_file", "buho-agent.log"), "name": "agent"}])
            cfg.setdefault("http_logs", [])
            headers = {"X-Buho-Agent-Id": str(cfg["agent_id"]), "X-Buho-Agent-Key": cfg["agent_key"]}
            state_path = str(Path(config_path).with_name("state.json"))
            state = load_json(state_path, {})
            last = defaultdict(float)
            sent_logs_minute = 0
            minute_bucket = int(time.time() // 60)
            while True:
                try:
                    now = time.time()
                    if int(now // 60) != minute_bucket:
                        minute_bucket = int(now // 60)
                        sent_logs_minute = 0
                    flush_spool(cfg, headers)
                    if now - last["heartbeat"] >= cfg["heartbeat_interval"]:
                        post_with_retry(cfg, headers, "/api/agents/heartbeat", {"status": "ONLINE", "metadata": {"agent_version": VERSION}})
                        last["heartbeat"] = now
                    if now - last["metrics"] >= cfg["metrics_interval"]:
                        metrics = collect_metrics()
                        for path in cfg.get("http_logs", []):
                            metrics.extend(parse_http_logs(path, state))
                        post_with_retry(cfg, headers, "/api/ingest/metrics", {"ts": utc_now(), "metrics": metrics})
                        last["metrics"] = now
                    if now - last["processes"] >= cfg["processes_interval"]:
                        processes, apps = collect_processes_and_apps()
                        services = [{"name": item.get("name"), "kind": "service", "ports": [], "metadata": {"status": item.get("status")}} for item in collect_services()]
                        post_with_retry(cfg, headers, "/api/ingest/processes", {"ts": utc_now(), "processes": processes})
                        post_with_retry(cfg, headers, "/api/ingest/apps", {"ts": utc_now(), "apps": apps + services})
                        last["processes"] = now
                    if now - last["logs"] >= cfg["logs_interval"]:
                        logs = collect_logs(cfg, state)
                        remaining = max(0, 2000 - sent_logs_minute)
                        logs = logs[:remaining]
                        if logs:
                            post_with_retry(cfg, headers, "/api/ingest/logs", {"logs": logs})
                            sent_logs_minute += len(logs)
                        last["logs"] = now
                    save_json(state_path, state)
                    if once:
                        return
                    time.sleep(1)
                except Exception as exc:
                    with open(cfg.get("log_file", "buho-agent.log"), "a", encoding="utf-8") as handle:
                        handle.write(f"{utc_now()} loop-error {exc}\\n")
                    if once:
                        raise
                    time.sleep(5)

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
    ).replace("\n        ", "\n").lstrip().rstrip() + "\n"


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
        $cfgJson = ($config | ConvertTo-Json -Depth 6)
        [System.IO.File]::WriteAllText($ConfigPath, $cfgJson, (New-Object System.Text.UTF8Encoding($false)))

        Write-Step "Creando entorno virtual"
        python -m venv (Join-Path $InstallRoot "venv")
        $PyExe = Join-Path $InstallRoot "venv\\Scripts\\python.exe"

        Write-Step "Validando config.json"
        & $PyExe -c "import json; import pathlib; p=pathlib.Path(r'$ConfigPath'); json.loads(p.read_text(encoding='utf-8-sig')); print('config json OK')"
        if ($LASTEXITCODE -ne 0) {{
            Write-ErrorStep "config.json inválido. Abortando instalación."
            exit 1
        }}

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

        $PyExeQuoted = '"' + $PyExe + '"'
        $AgentPyPathQuoted = '"' + $AgentPyPath + '"'
        $ConfigPathQuoted = '"' + $ConfigPath + '"'
        $TaskCommand = "$PyExeQuoted $AgentPyPathQuoted --run --config $ConfigPathQuoted"
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($IsAdmin) {{
            $createArgs = @('/Create', '/TN', 'BuhoAgent', '/SC', 'ONSTART', '/RU', 'SYSTEM', '/RL', 'HIGHEST', '/F', '/TR', $TaskCommand)
            Write-Step "Creando tarea programada BuhoAgent (SYSTEM/ONSTART)"
        }} else {{
            $createArgs = @('/Create', '/TN', 'BuhoAgent', '/SC', 'ONLOGON', '/RU', $env:USERNAME, '/F', '/TR', $TaskCommand)
            Write-Step "Creando tarea programada BuhoAgent (ONLOGON/$env:USERNAME)"
        }}

        & schtasks.exe @createArgs
        if ($LASTEXITCODE -ne 0) {{
            Write-ErrorStep "No se pudo crear la tarea programada BuhoAgent."
            Write-Host "Ejecuta manualmente:" -ForegroundColor Yellow
            Write-Host "schtasks /Create /TN \"BuhoAgent\" /SC ONSTART /RU \"SYSTEM\" /RL HIGHEST /F /TR \"$TaskCommand\"" -ForegroundColor Yellow
            Write-Host "o (sin admin):" -ForegroundColor Yellow
            Write-Host "schtasks /Create /TN \"BuhoAgent\" /SC ONLOGON /RU \"$env:USERNAME\" /F /TR \"$TaskCommand\"" -ForegroundColor Yellow
            Write-Host "Y luego ejecuta manualmente: $PyExeQuoted $AgentPyPathQuoted --run --config $ConfigPathQuoted" -ForegroundColor Yellow
            exit 1
        }}

        if ($IsAdmin) {{
            & schtasks.exe /Run /TN "BuhoAgent"
            if ($LASTEXITCODE -ne 0) {{
                Write-ErrorStep "No se pudo ejecutar la tarea BuhoAgent."
                Write-Host "Ejecuta manualmente: schtasks /Run /TN \"BuhoAgent\"" -ForegroundColor Yellow
                Write-Host "o directamente: $PyExeQuoted $AgentPyPathQuoted --run --config $ConfigPathQuoted" -ForegroundColor Yellow
                exit 1
            }}
        }} else {{
            Write-Host "[BuhoAgent] Aviso: iniciará al iniciar sesión." -ForegroundColor Yellow
        }}

        Write-Host "[BuhoAgent] Instalación completa ✅" -ForegroundColor Green
        Write-Host "[BuhoAgent] Logs: C:\\ProgramData\\BuhoAgent\\buho-agent.log" -ForegroundColor Green
        Write-Host "[BuhoAgent] Verifica ONLINE en: $BuhoUrl/agents/overview" -ForegroundColor Green
        """
    ).replace("\n        ", "\n").lstrip().rstrip() + "\n"


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
        now = timezone.now()
        offline_cutoff = now - timedelta(seconds=90)
        degraded_cutoff = now - timedelta(seconds=30)
        agents.filter(last_seen__lt=offline_cutoff).exclude(status=Agent.Status.OFFLINE).update(status=Agent.Status.OFFLINE)
        agents.filter(last_seen__lt=degraded_cutoff, last_seen__gte=offline_cutoff).exclude(status=Agent.Status.DEGRADED).update(status=Agent.Status.DEGRADED)
        agents.filter(last_seen__gte=degraded_cutoff).exclude(status=Agent.Status.ONLINE).update(status=Agent.Status.ONLINE)
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
        apps = DetectedApp.objects.filter(agent=agent).order_by('-last_seen')[:50]
        return render(request, 'agents/detail.html', {'agent': agent, 'heartbeats': agent.heartbeats.all()[:20], 'apps': apps})


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
{{"server_url":"{server_url}","token":"{token}","heartbeat_interval":15,"metrics_interval":15,"processes_interval":30,"logs_interval":15,"log_file":"$INSTALL_DIR/buho-agent.log","spool_file":"$INSTALL_DIR/spool.jsonl","logs_sources":[{{"type":"file","path":"$INSTALL_DIR/buho-agent.log","name":"agent"}}],"http_logs":["/var/log/nginx/access.log","/var/log/apache2/access.log"]}}
EOF
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -r <(curl -fsSL {server_url}/agents/download/requirements.txt) || true
if command -v systemctl >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/buho-agent.service" <<UNIT
[Unit]
Description=Buho Agent
After=network-online.target

[Service]
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/agent.py --run --config $INSTALL_DIR/config.json
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=5
StandardOutput=append:$INSTALL_DIR/buho-agent.log
StandardError=append:$INSTALL_DIR/buho-agent.log

[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload || true
  systemctl --user enable --now buho-agent.service || true
else
  nohup "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --run --config "$INSTALL_DIR/config.json" >>"$INSTALL_DIR/buho-agent.log" 2>&1 &
fi
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
        agent_code = build_agent_py()
        try:
            compile(agent_code, 'agent.py', 'exec')
        except Exception:
            logger.exception('agent.py generator produced invalid python')
            return HttpResponse('agent.py generator produced invalid python', status=500, content_type='text/plain')

        response = HttpResponse(agent_code, content_type='text/x-python')
        response['Content-Disposition'] = 'attachment; filename="agent.py"'
        return response


class AgentDownloadRequirementsView(View):
    def get(self, request):
        response = HttpResponse(AGENT_REQUIREMENTS, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="requirements.txt"'
        return response
