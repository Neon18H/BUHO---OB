import logging
import os
from textwrap import dedent
from datetime import timedelta

from django.contrib import messages
from django.db.models import Count, Max, Q
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from audit.utils import create_audit_log
from ui.permissions import RoleRequiredUIMixin

from .forms import TokenCreateForm
from .models import Agent, AgentCommand, AgentEnrollmentToken, DetectedApp, Incident, LogEntry, MetricPoint, NocturnalScanRun, ProcessSample, SecurityFinding


AGENT_REQUIREMENTS = "requests\npsutil\nyara-python\n"
logger = logging.getLogger(__name__)


def build_agent_py():
    return (
        """
        #!/usr/bin/env python3
        import argparse
        import hashlib
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

        VERSION = "0.5.0"
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

        def write_log(log_file, level, message, exc=None):
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            with open(log_file, "a", encoding="utf-8") as handle:
                handle.write(f"{utc_now()} [{level}] {message}\\n")
                if exc:
                    import traceback
                    handle.write(traceback.format_exc() + "\\n")

        def post_json(url, payload, headers=None, timeout=(3, 5)):
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
                    status_code, data = post_json(cfg["server_url"] + path, payload, headers=headers, timeout=(3, 5))
                    if status_code < 300:
                        return True
                    write_log(cfg.get("log_file", "C:/ProgramData/BuhoAgent/buho-agent.log"), "WARN", f"upload failed {path} status={status_code} body={data}")
                except Exception as exc:
                    write_log(cfg.get("log_file", "C:/ProgramData/BuhoAgent/buho-agent.log"), "ERROR", f"upload exception {path}: {exc}", exc=exc)
                time.sleep(wait)
            enqueue_spool(cfg["spool_file"], {"path": path, "payload": payload})
            return False

        def get_scan_state_path():
            if os.name == "nt":
                return "C:/ProgramData/BuhoAgent/scan_state.json"
            return "/var/lib/buhoagent/scan_state.json"

        def sha256_file(path):
            h = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    h.update(chunk)
            return h.hexdigest()

        def poll_command(cfg, headers):
            try:
                response = requests.get(cfg["server_url"] + "/api/agent/commands/poll", headers=headers, timeout=(3, 5))
                if response.status_code >= 300:
                    return None
                return response.json().get("command")
            except Exception:
                return None

        def ack_command(cfg, headers, command_id, status, progress=0, message="", stats=None):
            payload = {"command_id": command_id, "status": status, "progress": progress, "message": message, "stats": stats or {}}
            try:
                post_json(cfg["server_url"] + "/api/agent/commands/ack", payload, headers=headers, timeout=(3, 5))
            except Exception:
                pass

        def run_nocturnal_cycle(cfg, headers, state):
            noct = cfg.get("nocturnal") or {}
            paths = noct.get("paths") or (["C:/Windows/Temp"] if os.name == "nt" else ["/tmp", "/var/tmp"])
            max_files = int(noct.get("max_files_per_cycle", 200))
            max_size = int(noct.get("max_file_size_mb", 20)) * 1024 * 1024
            scan_state = load_json(get_scan_state_path(), {"files": {}})
            artifacts, findings = [], []
            scanned = 0
            for root in paths:
                if scanned >= max_files:
                    break
                p = Path(root)
                if not p.exists():
                    continue
                for fp in p.rglob("*"):
                    if scanned >= max_files:
                        break
                    try:
                        if not fp.is_file():
                            continue
                        stat = fp.stat()
                        if stat.st_size > max_size:
                            continue
                        prev = (scan_state.get("files") or {}).get(str(fp))
                        marker = f"{int(stat.st_mtime)}:{stat.st_size}"
                        if prev == marker:
                            continue
                        sha = sha256_file(fp)
                        artifacts.append({"path": redact(str(fp))[:255], "sha256": sha, "size": stat.st_size, "mtime": stat.st_mtime, "ts": utc_now()})
                        scan_state.setdefault("files", {})[str(fp)] = marker
                        scanned += 1
                    except Exception:
                        continue
            if artifacts:
                post_with_retry(cfg, headers, "/api/ingest/security/artifacts", {"artifacts": artifacts, "vt_threshold": int(noct.get("vt_threshold", 3))})
            if findings:
                post_with_retry(cfg, headers, "/api/ingest/security/findings", {"findings": findings})
            save_json(get_scan_state_path(), scan_state)
            state["nocturnal_stats"] = {
                "files_scanned": scanned,
                "hashes_checked": len(artifacts),
                "yara_matches": len(findings),
            }

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

        def detect_provider_and_apps():
            env = os.environ
            hints = {}
            provider = "OTHER"
            if any(k.startswith("RAILWAY_") for k in env):
                provider = "RAILWAY"
                hints["railway"] = True
            elif any(k.startswith("AWS_") for k in env):
                provider = "AWS"
            elif env.get("WEBSITE_INSTANCE_ID"):
                provider = "AZURE"
            elif env.get("GOOGLE_CLOUD_PROJECT"):
                provider = "GCP"
            elif os.path.exists("/.dockerenv"):
                provider = "ON_PREM"
            apps = []
            listen = defaultdict(list)
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN and conn.pid and conn.laddr:
                    listen[conn.pid].append(conn.laddr.port)
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    name = (proc.info.get("name") or "").lower()
                    cmd = " ".join(proc.info.get("cmdline") or []).lower()
                    runtime, framework, server = "", "", ""
                    if "gunicorn" in cmd or "uvicorn" in cmd or "python" in name:
                        runtime = "python"
                        if "django" in cmd or "manage.py" in cmd or env.get("DJANGO_SETTINGS_MODULE"):
                            framework = "django"
                    if "node" in name or "pm2" in cmd:
                        runtime = "node"
                    if "java" in name:
                        runtime = "java"
                    if "dotnet" in name:
                        runtime = "dotnet"
                    if "nginx" in name:
                        server = "nginx"
                    if runtime or server:
                        apps.append({"name": proc.info.get("name") or f"pid-{proc.info.get('pid')}", "kind": "web", "runtime": runtime, "framework": framework, "server": server, "pid": proc.info.get("pid"), "ports": sorted(set(listen.get(proc.info.get("pid"), []))), "process_hints": {"cmdline": cmd}, "metadata": {}})
                except Exception:
                    continue
            return provider, hints, apps

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
            cfg.setdefault("log_file", "C:/ProgramData/BuhoAgent/buho-agent.log")
            cfg.setdefault("spool_file", str(Path(config_path).with_name("spool.jsonl")))
            cfg.setdefault("heartbeat_interval", 15)
            cfg.setdefault("metrics_interval", 10)
            cfg.setdefault("processes_interval", 30)
            cfg.setdefault("logs_interval", 15)
            cfg.setdefault("discovery_interval", 300)
            cfg.setdefault("logs_sources", [{"type": "file", "path": cfg.get("log_file", "C:/ProgramData/BuhoAgent/buho-agent.log"), "name": "agent"}])
            cfg.setdefault("http_logs", [])
            cfg.setdefault("command_poll_interval", 12)
            cfg.setdefault("nocturnal", {"active": False})
            headers = {"X-Buho-Agent-Id": str(cfg["agent_id"]), "X-Buho-Agent-Key": cfg["agent_key"]}
            state_path = str(Path(config_path).with_name("state.json"))
            state = load_json(state_path, {})
            last = defaultdict(float)
            sent_logs_minute = 0
            minute_bucket = int(time.time() // 60)
            write_log(cfg["log_file"], "INFO", "agent loop started")
            while True:
                try:
                    now = time.time()
                    if int(now // 60) != minute_bucket:
                        minute_bucket = int(now // 60)
                        sent_logs_minute = 0
                    flush_spool(cfg, headers)
                    if now - last["command_poll"] >= cfg["command_poll_interval"]:
                        command = poll_command(cfg, headers)
                        if command and command.get("id"):
                            ctype = command.get("type")
                            if ctype == "START_NOCTURNAL_SCAN":
                                cfg["nocturnal"].update(command.get("payload") or {})
                                cfg["nocturnal"]["active"] = True
                                ack_command(cfg, headers, command["id"], "RUNNING", progress=1, message="Nocturnal scan running")
                            elif ctype == "STOP_NOCTURNAL_SCAN":
                                cfg["nocturnal"]["active"] = False
                                ack_command(cfg, headers, command["id"], "CANCELED", progress=100, message="Nocturnal scan stopped", stats=state.get("nocturnal_stats") or {})
                        last["command_poll"] = now
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
                        post_with_retry(cfg, headers, "/api/ingest/processes", {"ts": utc_now(), "processes": processes[:25]})
                        post_with_retry(cfg, headers, "/api/ingest/apps", {"ts": utc_now(), "apps": apps + services})
                        last["processes"] = now
                    if now - last["discovery"] >= cfg["discovery_interval"]:
                        provider, hints, discovered_apps = detect_provider_and_apps()
                        post_with_retry(cfg, headers, "/api/ingest/discovery", {"ts": utc_now(), "provider": provider, "tags": cfg.get("tags", []), "cloud_metadata": {"hostname": socket.gethostname()}, "hints": hints, "apps": discovered_apps})
                        last["discovery"] = now
                    if now - last["logs"] >= cfg["logs_interval"]:
                        logs = collect_logs(cfg, state)
                        remaining = max(0, 2000 - sent_logs_minute)
                        logs = logs[:remaining]
                        if logs:
                            post_with_retry(cfg, headers, "/api/ingest/logs", {"logs": logs})
                            sent_logs_minute += len(logs)
                        last["logs"] = now
                    if cfg.get("nocturnal", {}).get("active") and now - last["nocturnal"] >= int(cfg.get("nocturnal", {}).get("interval_seconds", 60)):
                        run_nocturnal_cycle(cfg, headers, state)
                        last["nocturnal"] = now
                    save_json(state_path, state)
                    if once:
                        return
                    time.sleep(1)
                except Exception as exc:
                    write_log(cfg.get("log_file", "C:/ProgramData/BuhoAgent/buho-agent.log"), "ERROR", f"loop exception: {exc}", exc=exc)
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
            try:
                main()
            except Exception as exc:
                write_log("C:/ProgramData/BuhoAgent/buho-agent.log", "ERROR", f"fatal crash: {exc}", exc=exc)
                raise
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
        $RunnerCmdPath = Join-Path $InstallRoot "run-agent.cmd"

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
            processes_interval = 30
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
        $RunnerScript = @"
@echo off
:loop
$PyExeQuoted $AgentPyPathQuoted --run --config $ConfigPathQuoted
timeout /t 5 /nobreak >nul
goto loop
"@
        [System.IO.File]::WriteAllText($RunnerCmdPath, $RunnerScript, (New-Object System.Text.UTF8Encoding($false)))
        $TaskCommand = '"' + $RunnerCmdPath + '"'
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
        agents = self.scoped_agents(request).annotate(last_metrics_at=Max("metric_points__ts"), last_processes_at=Max("process_samples__ts"), last_logs_at=Max("log_entries__ts"))
        provider = request.GET.get('provider', '')
        env = request.GET.get('env', '')
        if provider:
            agents = agents.filter(provider=provider)
        if env:
            agents = agents.filter(environment=env)
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
                'providers': Agent.Provider.choices,
                'envs': Agent.Environment.choices,
                'filters': {'provider': provider, 'env': env},
            },
        )


class AgentDetailView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True

    def post(self, request, agent_id):
        agent = get_object_or_404(self.scoped_agents(request), id=agent_id)
        action = request.POST.get('action')
        if action == 'start_nocturnal':
            payload = {
                'paths': [p.strip() for p in (request.POST.get('paths') or '').splitlines() if p.strip()],
                'yara_enabled': request.POST.get('yara_enabled') == 'on',
                'virustotal_enabled': request.POST.get('virustotal_enabled') == 'on',
                'max_files_per_cycle': int(request.POST.get('max_files_per_cycle') or 200),
                'interval_seconds': int(request.POST.get('interval_seconds') or 60),
                'max_file_size_mb': int(request.POST.get('max_file_size_mb') or 20),
                'vt_threshold': int(request.POST.get('vt_threshold') or 3),
            }
            AgentCommand.objects.create(
                organization=agent.organization,
                agent=agent,
                command_type=AgentCommand.CommandType.START_NOCTURNAL_SCAN,
                payload_json=payload,
                status=AgentCommand.Status.PENDING,
                issued_by=request.user,
            )
            messages.success(request, 'Acción Nocturna enviada al agente.')
        elif action == 'stop_nocturnal':
            AgentCommand.objects.create(
                organization=agent.organization,
                agent=agent,
                command_type=AgentCommand.CommandType.STOP_NOCTURNAL_SCAN,
                payload_json={},
                status=AgentCommand.Status.PENDING,
                issued_by=request.user,
            )
            messages.success(request, 'Comando de detención enviado.')
        return redirect('agents:detail', agent_id=agent.id)

    def get(self, request, agent_id):
        agent = get_object_or_404(self.scoped_agents(request), id=agent_id)
        create_audit_log(request=request, actor=request.user, action='VIEW_AGENT', target_type='Agent', target_id=str(agent.id))
        time_range = request.GET.get('time_range', '1h')
        minutes = {'15m': 15, '1h': 60, '24h': 1440}.get(time_range, 60)
        since = timezone.now() - timedelta(minutes=minutes)
        apps = DetectedApp.objects.filter(agent=agent).order_by('-last_seen')[:100]
        metrics = MetricPoint.objects.filter(agent=agent, ts__gte=since, name__in=['cpu.percent', 'mem.percent', 'disk.root.used_percent', 'net.bytes_recv', 'net.bytes_sent']).order_by('ts')
        labels, cpu_values, mem_values, disk_values, net_in, net_out = [], [], [], [], [], []
        grouped = {}
        for point in metrics:
            key = point.ts.replace(second=0, microsecond=0)
            grouped.setdefault(key, {})[point.name] = point.value
        for ts_key in sorted(grouped):
            labels.append(ts_key.strftime('%H:%M'))
            cpu_values.append(grouped[ts_key].get('cpu.percent', 0))
            mem_values.append(grouped[ts_key].get('mem.percent', 0))
            disk_values.append(grouped[ts_key].get('disk.root.used_percent', 0))
            net_in.append(grouped[ts_key].get('net.bytes_recv', 0))
            net_out.append(grouped[ts_key].get('net.bytes_sent', 0))
        logs = LogEntry.objects.filter(agent=agent).order_by('-ts')[:200]
        incidents = Incident.objects.filter(agent=agent).order_by('-last_seen')[:100]
        latest_process_ts = ProcessSample.objects.filter(agent=agent).order_by('-ts').values_list('ts', flat=True).first()
        processes = ProcessSample.objects.filter(agent=agent, ts=latest_process_ts).order_by('-cpu', '-mem')[:50] if latest_process_ts else []
        last_metrics_at = MetricPoint.objects.filter(agent=agent).order_by('-ts').values_list('ts', flat=True).first()
        last_logs_at = LogEntry.objects.filter(agent=agent).order_by('-ts').values_list('ts', flat=True).first()
        latest_run = NocturnalScanRun.objects.filter(agent=agent).order_by('-started_at').first()
        vt_available = bool(os.environ.get('VT_API_KEY'))
        return render(request, 'agents/detail.html', {
            'agent': agent,
            'heartbeats': agent.heartbeats.all()[:20],
            'apps': apps,
            'labels': labels,
            'cpu_values': cpu_values,
            'mem_values': mem_values,
            'disk_values': disk_values,
            'net_in': net_in,
            'net_out': net_out,
            'logs': logs,
            'incidents': incidents,
            'processes': processes,
            'time_range': time_range,
            'last_metrics_at': last_metrics_at,
            'last_processes_at': latest_process_ts,
            'last_logs_at': last_logs_at,
            'latest_nocturnal_run': latest_run,
            'vt_available': vt_available,
        })


class ThreatsOverviewView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True

    def get(self, request):
        findings = SecurityFinding.objects.filter(organization=request.user.organization)
        high_critical = findings.filter(severity__in=[SecurityFinding.Severity.HIGH, SecurityFinding.Severity.CRITICAL], status=SecurityFinding.Status.OPEN).count()
        recent = findings.select_related('agent').order_by('-last_seen')[:50]
        by_agent = findings.values('agent__name').annotate(total=Count('id')).order_by('-total')[:10]
        return render(request, 'agents/threats_overview.html', {'high_critical': high_critical, 'recent_findings': recent, 'by_agent': by_agent})


class AgentThreatsView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True

    def get(self, request, agent_id):
        agent = get_object_or_404(self.scoped_agents(request), id=agent_id)
        severity = request.GET.get('severity', '')
        status_filter = request.GET.get('status', '')
        findings = SecurityFinding.objects.filter(agent=agent)
        if severity:
            findings = findings.filter(severity=severity)
        if status_filter:
            findings = findings.filter(status=status_filter)
        return render(request, 'agents/agent_threats.html', {'agent': agent, 'findings': findings[:300], 'severity': severity, 'status_filter': status_filter})


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
