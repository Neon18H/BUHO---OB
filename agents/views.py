from textwrap import dedent

from django.contrib import messages
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from accounts.models import Organization
from audit.utils import create_audit_log
from ui.permissions import RoleRequiredUIMixin

from .forms import TokenCreateForm
from .models import Agent, AgentEnrollmentToken


class AgentOrganizationMixin:
    def scoped_organization(self, request):
        if request.user.role == 'SUPERADMIN':
            org_id = request.session.get('active_org_id')
            if org_id:
                return Organization.objects.filter(id=org_id).first()
            return None
        return request.user.organization

    def scoped_agents(self, request):
        org = self.scoped_organization(request)
        qs = Agent.objects.select_related('organization')
        return qs.filter(organization=org) if org else qs

    def scoped_tokens(self, request):
        org = self.scoped_organization(request)
        qs = AgentEnrollmentToken.objects.select_related('organization', 'created_by')
        return qs.filter(organization=org) if org else qs


class AgentsOverviewView(RoleRequiredUIMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}
    require_organization = True

    def get(self, request):
        agents = self.scoped_agents(request)
        create_audit_log(request=request, actor=request.user, action='VIEW_AGENT', target_type='AgentList', metadata={'count': agents.count()})
        return render(
            request,
            'agents/overview.html',
            {
                'agents': agents,
                'can_manage_tokens': request.user.is_superuser or request.user.role in {'SUPERADMIN', 'ORG_ADMIN'},
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
        can_manage_tokens = request.user.is_superuser or request.user.role in {'SUPERADMIN', 'ORG_ADMIN'}
        return render(
            request,
            'agents/install.html',
            {
                'form': TokenCreateForm(),
                'latest_token': latest_token,
                'server_url': server_url,
                'can_manage_tokens': can_manage_tokens,
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
            messages.error(request, 'Select an organization scope first.')
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
        request.session['latest_token_plain'] = token.token
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
        script = dedent("""#!/usr/bin/env bash
set -euo pipefail
BUHO_URL="__SERVER_URL__"
TOKEN="__TOKEN__"
HAS_SUDO=0; if command -v sudo >/dev/null 2>&1; then HAS_SUDO=1; fi
for bin in bash curl python3; do command -v "$bin" >/dev/null 2>&1 || { echo "missing $bin"; exit 1; }; done
if [[ "$HAS_SUDO" == "1" && $(id -u) -ne 0 ]]; then PREFIX="sudo"; else PREFIX=""; fi
if [[ -n "$PREFIX" || $(id -u) -eq 0 ]]; then INSTALL_DIR=/opt/buho-agent; CONF_DIR=/etc/buho-agent; LOG_FILE=/var/log/buho-agent.log; else INSTALL_DIR="$HOME/.buho-agent"; CONF_DIR="$HOME/.config/buho-agent"; LOG_FILE="$HOME/.buho-agent/buho-agent.log"; fi
$PREFIX mkdir -p "$INSTALL_DIR" "$CONF_DIR"
if python3 -m venv --help >/dev/null 2>&1; then python3 -m venv "$INSTALL_DIR/.venv" && PY="$INSTALL_DIR/.venv/bin/python"; else PY=python3; fi
$PY -m pip install --quiet --disable-pip-version-check requests psutil || true
cat > "$INSTALL_DIR/agent.py" <<'PYEOF'
import json, os, time, socket, platform, pathlib, re
from datetime import datetime, timezone
import requests, psutil
SERVER=os.environ.get('BUHO_URL'); TOKEN=os.environ.get('BUHO_TOKEN'); CONF=os.environ.get('BUHO_CONF'); LOG_FILE=os.environ.get('BUHO_LOG')
S=re.compile(r'(?i)(authorization:|bearer\s+[A-Za-z0-9\-_\.]+|api[_-]?key\s*=\s*\S+|password\s*=\s*\S+|token\s*=\s*\S+)')
def r(v): return S.sub('[REDACTED]', v or '')
def log(m): pathlib.Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True); open(LOG_FILE,'a').write(f"{datetime.utcnow().isoformat()} {m}\n")
def req(path,payload,h):
    try: return requests.post(SERVER+path,json=payload,headers=h,timeout=8)
    except Exception as e: log(f"request-error {e}"); return None
def enroll():
    if os.path.exists(CONF): return json.load(open(CONF))
    payload={'token':TOKEN,'hostname':socket.gethostname(),'ip_address':'127.0.0.1','os':platform.platform(),'arch':platform.machine(),'version':'0.1.0','name':socket.gethostname()}
    res=req('/api/agents/enroll',payload,{'Content-Type':'application/json'})
    if not res or res.status_code != 200: raise SystemExit('enroll failed')
    data=res.json(); pathlib.Path(CONF).parent.mkdir(parents=True, exist_ok=True); open(CONF,'w').write(json.dumps(data)); os.chmod(CONF,0o600); return data
def metrics():
    d=psutil.disk_usage('/'); n=psutil.net_io_counters(); m=psutil.virtual_memory()
    return [{'name':'cpu.percent','value':psutil.cpu_percent(),'unit':'%'},{'name':'mem.percent','value':m.percent,'unit':'%'},{'name':'disk.root.used_percent','value':d.percent,'unit':'%'},{'name':'net.bytes_sent','value':n.bytes_sent,'unit':'bytes'},{'name':'net.bytes_recv','value':n.bytes_recv,'unit':'bytes'},{'name':'load.1m','value':os.getloadavg()[0] if hasattr(os,'getloadavg') else 0,'unit':'load'}]
def procs():
    rows=[]
    for p in psutil.process_iter(['pid','name','username','cmdline','cpu_percent','memory_percent']):
        try: rows.append({'pid':p.info['pid'],'name':p.info.get('name') or 'n/a','cpu':p.info.get('cpu_percent') or 0,'mem':p.info.get('memory_percent') or 0,'user':p.info.get('username') or '', 'cmdline':r(' '.join(p.info.get('cmdline') or []))})
        except Exception: pass
    rows=sorted(rows,key=lambda x:(x['cpu'],x['mem']),reverse=True)[:25]
    return rows
def logs_tail():
    for p in ['/var/log/syslog','/var/log/messages']:
        if os.path.exists(p):
            try:
                tail_lines = open(p,'r',errors='ignore').read().splitlines()[-5:]
                return [{'ts':datetime.now(timezone.utc).isoformat(),'level':'INFO','source':'syslog','message':r(line.strip()),'fields':{}} for line in tail_lines if line.strip()]
            except Exception:
                return []
    return []
def loop():
    conf=enroll(); h={'X-Buho-Agent-Id':str(conf['agent_id']),'X-Buho-Agent-Key':conf['agent_key']}; i=0
    while True:
        i+=1
        req('/api/agents/heartbeat',{'status':'ONLINE','metadata':{'uptime':time.time(),'agent_version':'0.1.0'}},h)
        req('/api/ingest/metrics',{'ts':datetime.now(timezone.utc).isoformat(),'metrics':metrics()},h)
        if i % 2 == 0: req('/api/ingest/processes',{'ts':datetime.now(timezone.utc).isoformat(),'processes':procs()},h)
        req('/api/ingest/logs',{'logs':logs_tail()},h)
        time.sleep(10)
if __name__=='__main__':
    backoff=2
    while True:
        try: loop()
        except Exception as e: log(f'loop-error {e}'); time.sleep(backoff); backoff=min(backoff*2,60)
PYEOF
cat > "$INSTALL_DIR/buho-agent.env" <<EOF
BUHO_URL=$BUHO_URL
BUHO_TOKEN=$TOKEN
BUHO_CONF=$CONF_DIR/config.json
BUHO_LOG=$LOG_FILE
EOF
if command -v systemctl >/dev/null 2>&1 && [[ -n "$PREFIX" || $(id -u) -eq 0 ]]; then
$PREFIX tee /etc/systemd/system/buho-agent.service >/dev/null <<EOF
[Unit]
Description=Buho Agent
After=network.target
[Service]
Type=simple
EnvironmentFile=$INSTALL_DIR/buho-agent.env
ExecStart=$PY $INSTALL_DIR/agent.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF
$PREFIX systemctl daemon-reload
$PREFIX systemctl enable --now buho-agent
echo "Buho agent activo con systemd"
else
nohup $PY "$INSTALL_DIR/agent.py" > "$INSTALL_DIR/agent.out" 2>&1 &
echo "No systemd/root. Running in user mode (nohup)."
fi
""").replace('__SERVER_URL__', server_url).replace('__TOKEN__', token)
        response = HttpResponse(script, content_type='text/x-shellscript')
        response['Content-Disposition'] = 'attachment; filename="buho-agent-linux.sh"'
        return response


class AgentDownloadWindowsView(View):
    def get(self, request):
        token = request.GET.get('token', '')
        if not token:
            return HttpResponseBadRequest('token required')
        server_url = request.build_absolute_uri('/').rstrip('/')
        script = dedent("""$BuhoUrl = "__SERVER_URL__"
$Token = "__TOKEN__"
$Root = Join-Path $env:USERPROFILE ".buho-agent"
New-Item -ItemType Directory -Force -Path $Root | Out-Null
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Host "Python3 is required"; exit 1 }
$agent = @"
import os,time,socket,platform,requests,json
url=os.environ.get('BUHO_URL'); token=os.environ.get('BUHO_TOKEN'); conf=os.path.join(os.environ.get('BUHO_ROOT'),'config.json')
def post(p,d,h=None): return requests.post(url+p,json=d,headers=h or {},timeout=8)
if os.path.exists(conf): c=json.load(open(conf))
else:
 r=post('/api/agents/enroll',{'token':token,'hostname':socket.gethostname(),'ip_address':'127.0.0.1','os':platform.platform(),'arch':platform.machine(),'version':'0.1.0'})
 c=r.json(); open(conf,'w').write(json.dumps(c))
h={'X-Buho-Agent-Id':str(c['agent_id']),'X-Buho-Agent-Key':c['agent_key']}
while True:
 post('/api/agents/heartbeat',{'status':'ONLINE','metadata':{'agent_version':'0.1.0'}},h)
 post('/api/ingest/metrics',{'metrics':[{'name':'cpu.percent','value':0,'unit':'%'}]},h)
 time.sleep(10)
"@
Set-Content -Path (Join-Path $Root "agent.py") -Value $agent
$env:BUHO_URL=$BuhoUrl; $env:BUHO_TOKEN=$Token; $env:BUHO_ROOT=$Root
python (Join-Path $Root "agent.py")
""").replace('__SERVER_URL__', server_url).replace('__TOKEN__', token)
        response = HttpResponse(script, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="buho-agent-windows.ps1"'
        return response


class AgentDownloadLinuxPyView(View):
    def get(self, request):
        token = request.GET.get('token', '')
        if not token:
            return HttpResponseBadRequest('token required')
        server_url = request.build_absolute_uri('/').rstrip('/')
        py = f"import os; print('Use linux.sh installer for full setup. URL={server_url}, token={token}')\n"
        response = HttpResponse(py, content_type='text/x-python')
        response['Content-Disposition'] = 'attachment; filename="buho-agent-linux.py"'
        return response
