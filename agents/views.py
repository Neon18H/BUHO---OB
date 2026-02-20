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
from buho.runtime import get_public_base_url
from accounts.models import Organization
from ui.permissions import RoleRequiredUIMixin

from .forms import TokenCreateForm
from .models import Agent, AgentCommand, AgentConfig, AgentEnrollmentToken, DetectedApp, Incident, LogEntry, MetricPoint, NocturnalScanRun, ProcessSample, SecurityFinding, ThreatFinding


AGENT_REQUIREMENTS = "requests\npsutil\nyara-python\n"
logger = logging.getLogger(__name__)


def build_agent_py():
    return (
        """
        #!/usr/bin/env python3
        import argparse
        import getpass
        import hashlib
        import json
        import os
        import platform
        import re
        import socket
        import subprocess
        import sys
        import time
        import traceback
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
                    handle.write(traceback.format_exc() + "\\n")

        def get_runtime_identity():
            username = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
            try:
                username = getpass.getuser() or username
            except Exception:
                pass
            is_system = username.lower() in {"system", "nt authority\\system"}
            return username, is_system

        def log_startup(cfg):
            username, is_system = get_runtime_identity()
            write_log(
                cfg["log_file"],
                "INFO",
                "startup "
                + f"agent_id={cfg.get('agent_id', 'pending')} "
                + f"server_url={cfg.get('server_url')} "
                + f"interval={cfg.get('heartbeat_interval')} "
                + f"platform={platform.platform()} "
                + f"username={username} "
                + f"is_system={is_system}",
            )

        def install_global_excepthook(log_file):
            def _hook(exc_type, exc, tb):
                with open(log_file, "a", encoding="utf-8") as handle:
                    handle.write(f"{utc_now()} [ERROR] unhandled exception: {exc}\\n")
                    handle.write("".join(traceback.format_exception(exc_type, exc, tb)) + "\\n")
            sys.excepthook = _hook

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

        def poll_commands(cfg, headers):
            try:
                response = requests.get(cfg["server_url"] + "/api/agent/commands/poll", headers=headers, timeout=(3, 5))
                if response.status_code >= 300:
                    return []
                return response.json().get("commands") or []
            except Exception:
                return []

        def send_command_result(cfg, headers, command_id, ok=True, result=None, error=""):
            payload = {"command_id": command_id, "status": "DONE" if ok else "FAILED", "result": result or {}, "error": error}
            try:
                post_json(cfg["server_url"] + "/api/agent/commands/result", payload, headers=headers, timeout=(3, 5))
            except Exception:
                pass

        def _compile_demo_rules():
            try:
                import yara
                return yara.compile(source='rule SuspiciousScript { strings: $a = "Invoke-WebRequest" nocase condition: $a }')
            except Exception:
                return None

        def scan_yara(cfg, payload):
            rules = _compile_demo_rules()
            paths = payload.get("paths") or (["C:/Users", "C:/ProgramData"] if os.name == "nt" else ["/home", "/var/www"])
            exclusions = set(payload.get("exclusions") or ["venv", ".git", "node_modules", "Windows\\WinSxS"])
            max_files = int(payload.get("max_files", 2000))
            max_file_mb = int(payload.get("max_file_mb", 30))
            findings, errors = [], []
            scanned = 0
            for root in paths:
                if scanned >= max_files:
                    break
                rp = Path(root)
                if not rp.exists():
                    continue
                for fp in rp.rglob("*"):
                    if scanned >= max_files:
                        break
                    try:
                        if any(ex in str(fp) for ex in exclusions) or not fp.is_file():
                            continue
                        if fp.stat().st_size > max_file_mb * 1024 * 1024:
                            continue
                        scanned += 1
                        sha = sha256_file(fp)
                        matches = rules.match(str(fp)) if rules else []
                        for m in matches:
                            findings.append({"file_path": str(fp), "file_hash_sha256": sha, "yara_rule": m.rule, "yara_tags": m.tags, "severity": "HIGH" if "malware" in m.tags else "MED"})
                    except Exception as exc:
                        errors.append(str(exc)[:180])
                        continue
            return {"findings": findings, "scanned_files": scanned, "matched": len(findings), "duration_sec": 0, "errors": errors}

        def quarantine_file(payload):
            source = payload.get("file_path")
            if not source:
                return {"error": "missing file_path"}
            src = Path(source)
            if not src.exists():
                return {"error": "file not found"}
            qdir = Path("C:/ProgramData/BuhoAgent/quarantine" if os.name == "nt" else "/var/lib/buho-agent/quarantine")
            qdir.mkdir(parents=True, exist_ok=True)
            target = qdir / f"{int(time.time())}-{sha256_file(src)}-{src.name}"
            src.rename(target)
            return {"quarantine_path": str(target)}


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
                    pattern = r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+([^\\s]+)[^"]*"\\s+(\\d{3})'
                    match = re.search(pattern, line)
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
            install_global_excepthook(cfg["log_file"])
            headers = {"X-Buho-Agent-Id": str(cfg["agent_id"]), "X-Buho-Agent-Key": cfg["agent_key"]}
            state_path = str(Path(config_path).with_name("state.json"))
            state = load_json(state_path, {})
            last = defaultdict(float)
            sent_logs_minute = 0
            minute_bucket = int(time.time() // 60)
            log_startup(cfg)
            write_log(cfg["log_file"], "INFO", "agent loop started")
            while True:
                try:
                    now = time.time()
                    if int(now // 60) != minute_bucket:
                        minute_bucket = int(now // 60)
                        sent_logs_minute = 0
                    flush_spool(cfg, headers)
                    if now - last["command_poll"] >= cfg["command_poll_interval"]:
                        commands = poll_commands(cfg, headers)
                        for command in commands:
                            ctype = command.get("type")
                            try:
                                if ctype in {"NIGHT_SCAN", "START_NOCTURNAL_SCAN"}:
                                    result = scan_yara(cfg, command.get("payload") or {})
                                    send_command_result(cfg, headers, command["id"], ok=True, result=result)
                                elif ctype == "QUARANTINE_FILE":
                                    result = quarantine_file(command.get("payload") or {})
                                    send_command_result(cfg, headers, command["id"], ok=("error" not in result), result=result, error=result.get("error", ""))
                                else:
                                    send_command_result(cfg, headers, command["id"], ok=False, error=f"unsupported command {ctype}")
                            except Exception as exc:
                                send_command_result(cfg, headers, command["id"], ok=False, error=str(exc))
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
            install_global_excepthook("C:/ProgramData/BuhoAgent/buho-agent.log")
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
        fr"""
        $ErrorActionPreference = "Stop"
        $BuhoUrl = "{server_url}"
        $Token = "{token}"
        $InstallRoot = "C:\ProgramData\BuhoAgent"
        $ConfigPath = Join-Path $InstallRoot "config.json"
        $LogPath = Join-Path $InstallRoot "buho-agent.log"
        $InstallLogPath = Join-Path $InstallRoot "install.log"
        $AgentPyPath = Join-Path $InstallRoot "agent.py"
        $ReqPath = Join-Path $InstallRoot "requirements.txt"
        $RunnerCmdPath = Join-Path $InstallRoot "run-agent.cmd"
        $RepairScriptPath = Join-Path $InstallRoot "run-manual.ps1"

        function Write-InstallLog($message, $level = "INFO") {{
            $line = "$(Get-Date -Format o) [$level] $message"
            Add-Content -Path $InstallLogPath -Value $line -Encoding UTF8
        }}

        function Write-Step($message) {{
            Write-InstallLog $message
            Write-Host "[BuhoAgent] $message" -ForegroundColor Cyan
        }}

        function Write-ErrorStep($message) {{
            Write-InstallLog $message "ERROR"
            Write-Host "[BuhoAgent] ERROR: $message" -ForegroundColor Red
        }}

        function Write-RepairInstructions($cause = "") {{
            $manualCmd = '& "C:\ProgramData\BuhoAgent\venv\Scripts\python.exe" "C:\ProgramData\BuhoAgent\agent.py" --run --config "C:\ProgramData\BuhoAgent\config.json"'
            $manualCmdWithLog = $manualCmd + ' >> "' + $LogPath + '" 2>&1'
            if ($cause) {{
                Write-ErrorStep "Causa probable: $cause"
            }}
            Write-Step "Comando manual de reparación:"
            Write-Host $manualCmd -ForegroundColor Yellow
            Write-Step "Comando manual con logs (recomendado):"
            Write-Host $manualCmdWithLog -ForegroundColor Yellow
            Write-Step "Script de reparación: $RepairScriptPath"
        }}

        if ($PSVersionTable.PSVersion.Major -lt 5) {{ Write-Host "PowerShell 5+ requerido." -ForegroundColor Red; exit 1 }}
        if (-not (Get-Command python -ErrorAction SilentlyContinue)) {{
            Write-Host "Python 3 no encontrado en PATH. Instálalo desde https://www.python.org/downloads/windows/." -ForegroundColor Yellow
            exit 1
        }}

        New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
        New-Item -ItemType File -Path $InstallLogPath -Force | Out-Null
        Write-Step "Inicio de instalación"
        Write-Step "Descargando agent.py y requirements.txt"
        Invoke-WebRequest -Uri "$BuhoUrl/agents/download/agent.py" -OutFile $AgentPyPath
        Invoke-WebRequest -Uri "$BuhoUrl/agents/download/requirements.txt" -OutFile $ReqPath

        $cfg = [ordered]@{{
            server_url = $BuhoUrl
            token = $Token
            heartbeat_interval = 15
            metrics_interval = 15
            processes_interval = 30
            logs_interval = 15
            discovery_interval = 300
            command_poll_interval = 12
            log_file = $LogPath
            spool_file = (Join-Path $InstallRoot "spool.jsonl")
            logs_sources = @(@{{ type = "file"; path = $LogPath; name = "agent" }})
            http_logs = @("C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log")
            tags = @("windows")
            nocturnal = @{{ active = $false; paths = @("C:\Windows\Temp") }}
        }}
        $cfgJson = $cfg | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText($ConfigPath, $cfgJson, (New-Object System.Text.UTF8Encoding($false)))

        $PyExe = (Get-Command python).Source
        Write-Step "Python detectado en $PyExe"
        Write-Step "Creando virtualenv"
        & $PyExe -m venv (Join-Path $InstallRoot "venv")
        $PyExe = Join-Path $InstallRoot "venv\Scripts\python.exe"

        Write-Step "Validando JSON de config"
        $configCheck = & $PyExe -c "import json; import pathlib; p=pathlib.Path(r'$ConfigPath'); json.loads(p.read_text(encoding='utf-8-sig')); print('config json OK')" 2>&1
        $configCheck | ForEach-Object {{ Write-InstallLog $_ }}
        if ($LASTEXITCODE -ne 0) {{
            Write-ErrorStep "config.json inválido. Abortando instalación."
            exit 1
        }}

        Write-Step "Instalando dependencias"
        & $PyExe -m pip install --disable-pip-version-check -r $ReqPath 2>&1 | Tee-Object -FilePath $InstallLogPath -Append | Out-Null

        Write-Step "Validando sintaxis de agent.py"
        $compileOutput = & $PyExe -m py_compile $AgentPyPath 2>&1
        $compileOutput | ForEach-Object {{ Write-InstallLog $_ }}
        if ($LASTEXITCODE -ne 0) {{
            Write-ErrorStep "agent.py tiene error de sintaxis"
            $compileOutput | ForEach-Object {{ Write-Host $_ -ForegroundColor Red }}
            exit 1
        }}

        Write-Step "Creando script run-agent.cmd con logging"
        $RunnerScript = @"
@echo off
chcp 65001 >nul
cd /d C:\ProgramData\BuhoAgent
echo [start] %date% %time% >> buho-agent.log
:loop
"$PyExe" "$AgentPyPath" --run --config "$ConfigPath" >> "$LogPath" 2>&1
timeout /t 5 /nobreak >nul
goto loop
"@
        [System.IO.File]::WriteAllText($RunnerCmdPath, $RunnerScript, (New-Object System.Text.UTF8Encoding($false)))

        Write-Step "Creando run-manual.ps1"
        $RepairScript = @"
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Set-Location "C:\ProgramData\BuhoAgent"
Add-Content -Path "C:\ProgramData\BuhoAgent\buho-agent.log" -Value "[manual-start] $(Get-Date -Format o)"
& "$PyExe" "$AgentPyPath" --run --config "$ConfigPath" >> "$LogPath" 2>&1
"@
        [System.IO.File]::WriteAllText($RepairScriptPath, $RepairScript, (New-Object System.Text.UTF8Encoding($false)))

        Write-Step "Ejecutando enroll"
        & $PyExe $AgentPyPath --enroll --config $ConfigPath 2>&1 | Tee-Object -FilePath $InstallLogPath -Append | Out-Null
        if ($LASTEXITCODE -ne 0) {{
            Write-ErrorStep "Enroll falló. No se creó tarea programada."
            Write-RepairInstructions "token inválido, URL inaccesible o bloqueo de red durante enroll"
            exit 1
        }}

        $TaskCommand = 'cmd.exe /c ""C:\ProgramData\BuhoAgent\run-agent.cmd""'
        $createArgs = @('/Create', '/TN', 'BuhoAgent', '/SC', 'ONSTART', '/RU', 'SYSTEM', '/RL', 'HIGHEST', '/F', '/TR', $TaskCommand)
        Write-Step "Creando tarea programada BuhoAgent (SYSTEM/ONSTART)"
        & schtasks.exe @createArgs 2>&1 | Tee-Object -FilePath $InstallLogPath -Append | Out-Null
        if ($LASTEXITCODE -ne 0) {{
            Write-ErrorStep "No se pudo crear la tarea programada BuhoAgent."
            Write-Host "Ejecuta manualmente:" -ForegroundColor Yellow
            Write-Host 'schtasks /Create /TN "BuhoAgent" /SC ONSTART /RU "SYSTEM" /RL HIGHEST /F /TR "' + $TaskCommand + '"' -ForegroundColor Yellow
            Write-RepairInstructions "error al registrar la tarea programada"
            exit 1
        }}

        $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
        if ($battery) {{
            Write-Step "Dispositivo con batería detectado; deshabilitando stop-on-battery para robustez"
        }}
        try {{
            $task = Get-ScheduledTask -TaskName "BuhoAgent" -ErrorAction Stop
            $task.Settings.DisallowStartIfOnBatteries = $false
            $task.Settings.StopIfGoingOnBatteries = $false
            Set-ScheduledTask -TaskName "BuhoAgent" -Settings $task.Settings | Out-Null
            Write-Step "Configuración de energía aplicada a la tarea"
        }} catch {{
            Write-InstallLog "No se pudo ajustar configuración de energía: $($_.Exception.Message)" "WARN"
        }}

        Write-Step "Ejecutando smoke test de tarea"
        $smokeOk = $false
        try {{
            Start-ScheduledTask -TaskName "BuhoAgent" -ErrorAction SilentlyContinue | Out-Null
            & schtasks.exe /Run /TN "BuhoAgent" 2>&1 | Tee-Object -FilePath $InstallLogPath -Append | Out-Null
            Start-Sleep -Seconds 5

            $taskDetails = & schtasks.exe /Query /TN "BuhoAgent" /V /FO LIST 2>&1
            $taskDetails | Tee-Object -FilePath $InstallLogPath -Append | Out-Null

            $taskStateMatch = $taskDetails | Select-String -Pattern '^Status:\s*(.+)$' | Select-Object -First 1
            $taskLastResultMatch = $taskDetails | Select-String -Pattern '^Last Run Result:\s*(.+)$' | Select-Object -First 1
            $taskState = if ($taskStateMatch) {{ $taskStateMatch.Matches[0].Groups[1].Value }} else {{ 'unknown' }}
            $taskLastResult = if ($taskLastResultMatch) {{ $taskLastResultMatch.Matches[0].Groups[1].Value }} else {{ 'unknown' }}

            Start-Sleep -Seconds 5
            $hasLog = Test-Path $LogPath
            $logSize = if ($hasLog) {{ (Get-Item $LogPath).Length }} else {{ 0 }}
            $hasLogData = $hasLog -and $logSize -gt 0

            $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {{
                ($_.Name -match '^python(\.exe)?$' -or $_.Name -match '^cmd(\.exe)?$') -and $_.CommandLine -like '*BuhoAgent\\agent.py*'
            }}
            if (-not $procs -or $procs.Count -eq 0) {{
                Write-InstallLog "Smoke test: no se detectaron procesos agent.py tras ejecutar tarea" "WARN"
                $hasProcess = $false
            }} else {{
                $hasProcess = $true
                Write-InstallLog "Smoke test: procesos detectados=$($procs.Count)" "INFO"
            }}

            if ($hasProcess -or $hasLogData) {{
                $smokeOk = $true
                Write-Step "Smoke test OK: tarea ejecutada con evidencias (proceso/log)"
            }} else {{
                Write-InstallLog "Smoke test sin evidencias. Estado tarea=$taskState último resultado=$taskLastResult" "WARN"
                & schtasks.exe /Query /TN "BuhoAgent" /V /FO LIST 2>&1 | Tee-Object -FilePath $InstallLogPath -Append | Out-Null
                Write-Host '[BuhoAgent] WARNING: smoke test sin evidencia de ejecución.' -ForegroundColor Yellow
                Write-Host '1) schtasks /Run /TN "BuhoAgent"' -ForegroundColor Yellow
                Write-Host '2) type C:\ProgramData\BuhoAgent\buho-agent.log' -ForegroundColor Yellow
                Write-Host '3) powershell -ExecutionPolicy Bypass -File "C:\ProgramData\BuhoAgent\run-manual.ps1"' -ForegroundColor Yellow
                Write-RepairInstructions "la tarea no dejó proceso/log luego del arranque"
            }}
        }} catch {{
            Write-InstallLog "Smoke test warning: $($_.Exception.Message)" "WARN"
            Write-Host '[BuhoAgent] WARNING: smoke test lanzó excepción (no fatal).' -ForegroundColor Yellow
            Write-RepairInstructions "smoke test con excepción no fatal"
        }}

        if (-not $smokeOk) {{
            Write-InstallLog "Instalación completada con warning de smoke test" "WARN"
        }}

        Write-Step "Manual repair"
        Write-Host '& "C:\ProgramData\BuhoAgent\venv\Scripts\python.exe" "C:\ProgramData\BuhoAgent\agent.py" --run --config "C:\ProgramData\BuhoAgent\config.json"' -ForegroundColor Yellow
        Write-Host "[BuhoAgent] Instalación completa ✅" -ForegroundColor Green
        Write-Host "[BuhoAgent] Logs agente: C:\ProgramData\BuhoAgent\buho-agent.log" -ForegroundColor Green
        Write-Host "[BuhoAgent] Logs instalador: C:\ProgramData\BuhoAgent\install.log" -ForegroundColor Green
        Write-Host '[BuhoAgent] Tail de logs: Get-Content "C:\ProgramData\BuhoAgent\buho-agent.log" -Tail 200 -Wait' -ForegroundColor Green
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
        try:
            create_audit_log(request=request, actor=request.user, action='VIEW_AGENT', target_type='AgentList', metadata={'count': agents.count()})
        except Exception as exc:
            logger.warning('Audit log failed for agents overview user=%s: %s', request.user.id, exc)
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
    missing_organization_redirect_url = 'auth_register'

    def post(self, request, agent_id):
        agent = get_object_or_404(self.scoped_agents(request), id=agent_id)
        action = request.POST.get('action')
        if action == 'run_night_scan':
            paths = [p.strip() for p in (request.POST.get('paths') or '').splitlines() if p.strip()]
            exclusions = [p.strip() for p in (request.POST.get('exclusions') or '').splitlines() if p.strip()]
            AgentCommand.objects.create(organization=agent.organization, agent=agent, command_type=AgentCommand.CommandType.NIGHT_SCAN, payload_json={'paths': paths, 'exclusions': exclusions, 'vt': request.POST.get('virustotal_enabled') == 'on'}, status=AgentCommand.Status.PENDING, issued_by=request.user)
            messages.success(request, 'Acción Nocturna enviada al agente.')
        elif action == 'quarantine_file':
            AgentCommand.objects.create(organization=agent.organization, agent=agent, command_type=AgentCommand.CommandType.QUARANTINE_FILE, payload_json={'file_path': request.POST.get('file_path', ''), 'method': 'move', 'reason': request.POST.get('reason', 'manual action')}, status=AgentCommand.Status.PENDING, issued_by=request.user)
            messages.success(request, 'Comando de cuarentena enviado.')
        elif action == 'ack_finding':
            ThreatFinding.objects.filter(id=request.POST.get('finding_id'), organization=agent.organization, agent=agent).update(status=ThreatFinding.Status.ACK)
            messages.success(request, 'Finding marcado como revisado.')
        return redirect('agents:detail', agent_id=agent.id)

    def _metrics_payload(self, agent):
        metric_names = ['cpu.percent', 'mem.percent', 'disk.root.used_percent', 'net.bytes_sent', 'net.bytes_recv', 'gpu.percent']
        points = MetricPoint.objects.filter(agent=agent, name__in=metric_names).order_by('-ts')[:600]
        grouped = {}
        for point in reversed(list(points)):
            key = point.ts.replace(second=0, microsecond=0)
            grouped.setdefault(key, {})[point.name] = point.value
        timestamps = list(grouped.keys())[-60:]
        labels = [ts.strftime('%H:%M') for ts in timestamps]
        series = {name: [grouped[ts].get(name, 0) for ts in timestamps] for name in metric_names}
        latest = {name: MetricPoint.objects.filter(agent=agent, name=name).order_by('-ts').first() for name in metric_names}
        return labels, series, latest

    def get(self, request, agent_id):
        agent = get_object_or_404(self.scoped_agents(request), id=agent_id)
        labels, series, latest = self._metrics_payload(agent)
        latest_process_ts = ProcessSample.objects.filter(agent=agent).order_by('-ts').values_list('ts', flat=True).first()
        cfg, _ = AgentConfig.objects.get_or_create(organization=agent.organization, agent=agent, defaults={'scan_paths': ['C:\\Users', 'C:\\ProgramData'] if 'win' in (agent.os or '').lower() else ['/home', '/var/www'], 'exclusions': ['venv', '.git', 'node_modules', 'Windows\\WinSxS']})
        logs = LogEntry.objects.filter(agent=agent).order_by('-ts')[:200]
        return render(request, 'agents/detail.html', {
            'agent': agent,
            'agent_tabs': ['metrics', 'processes', 'apps', 'logs', 'health', 'night-ops'],
            'labels': labels,
            'series': {'cpu': series.get('cpu.percent', []), 'ram': series.get('mem.percent', []), 'disk': series.get('disk.root.used_percent', []), 'net_out': series.get('net.bytes_sent', []), 'net_in': series.get('net.bytes_recv', []), 'gpu': series.get('gpu.percent', [])},
            'kpis': {
                'cpu': latest['cpu.percent'].value if latest['cpu.percent'] else None,
                'ram': latest['mem.percent'].value if latest['mem.percent'] else None,
                'disk': latest['disk.root.used_percent'].value if latest['disk.root.used_percent'] else None,
                'net': latest['net.bytes_sent'].value if latest['net.bytes_sent'] else None,
                'gpu': latest['gpu.percent'].value if latest['gpu.percent'] else None,
            },
            'apps': DetectedApp.objects.filter(agent=agent).order_by('-created_at')[:100],
            'logs': logs,
            'incidents': Incident.objects.filter(agent=agent).order_by('-created_at')[:100],
            'processes': ProcessSample.objects.filter(agent=agent, ts=latest_process_ts).order_by('-cpu', '-mem')[:20] if latest_process_ts else [],
            'latest_nocturnal_run': AgentCommand.objects.filter(agent=agent, command_type=AgentCommand.CommandType.NIGHT_SCAN).order_by('-created_at').first(),
            'findings': ThreatFinding.objects.filter(agent=agent).order_by('-created_at')[:120],
            'agent_config': cfg,
            'vt_available': bool(cfg.vt_api_key_masked),
        })


class AgentDetailTabView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True
    missing_organization_redirect_url = 'auth_register'

    def get(self, request, agent_id, tab):
        return redirect('agents:detail', agent_id=agent_id)

class ThreatsOverviewView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True

    def get(self, request):
        findings = ThreatFinding.objects.filter(organization=request.user.organization)
        high_critical = findings.filter(severity__in=[ThreatFinding.Severity.HIGH, ThreatFinding.Severity.CRIT], status=ThreatFinding.Status.OPEN).count()
        recent = findings.select_related('agent').order_by('-created_at')[:50]
        by_agent = findings.values('agent__name').annotate(total=Count('id')).order_by('-total')[:10]
        return render(request, 'agents/threats_overview.html', {'high_critical': high_critical, 'recent_findings': recent, 'by_agent': by_agent})


class AgentThreatsView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True

    def get(self, request, agent_id):
        agent = get_object_or_404(self.scoped_agents(request), id=agent_id)
        severity = request.GET.get('severity', '')
        status_filter = request.GET.get('status', '')
        findings = ThreatFinding.objects.filter(agent=agent)
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
        server_url = get_public_base_url(request)
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
        if org is None and request.user.is_superuser:
            org = request.user.organization or Organization.objects.order_by('id').first()
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
        server_url = get_public_base_url(request)
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
        server_url = get_public_base_url(request)
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
