import json
import secrets

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from accounts.models import Organization
from audit.utils import create_audit_log
from ui.permissions import RoleRequiredMixin

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


class AgentsOverviewView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        agents = self.scoped_agents(request)
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


class AgentDetailView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request, agent_id):
        agent = get_object_or_404(self.scoped_agents(request), id=agent_id)
        create_audit_log(request=request, actor=request.user, action='VIEW_AGENT', target_type='Agent', target_id=str(agent.id))
        return render(request, 'agents/detail.html', {'agent': agent, 'heartbeats': agent.heartbeats.all()[:20]})


class AgentsInstallView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        latest_token = self.scoped_tokens(request).first()
        return render(request, 'agents/install.html', {'form': TokenCreateForm(), 'latest_token': latest_token})


class TokensView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def get(self, request):
        tokens = self.scoped_tokens(request)
        create_audit_log(request=request, actor=request.user, action='VIEW_TOKENS', target_type='AgentEnrollmentToken', metadata={'count': tokens.count()})
        return render(request, 'agents/tokens.html', {'tokens': tokens, 'form': TokenCreateForm()})


class TokenCreateView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

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


class TokenRevokeView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

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


class AgentDownloadLinuxView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        token = request.GET.get('token', '')
        create_audit_log(request=request, actor=request.user, action='DOWNLOAD_AGENT', target_type='AgentDownload', metadata={'platform': 'linux'})
        server_url = request.build_absolute_uri('/').rstrip('/')
        script = f'''#!/usr/bin/env bash
set -e
BUHO_URL="{server_url}"
TOKEN="{token}"
INSTALL_DIR="/opt/buho-agent"
mkdir -p "$INSTALL_DIR"
cat > "$INSTALL_DIR/agent.py" <<'EOF'
import json, os, time, socket, platform, urllib.request
BUHO_URL = os.environ.get("BUHO_URL", "{server_url}")
TOKEN = os.environ.get("BUHO_TOKEN", "{token}")
CONF = "/opt/buho-agent/config.json"

def post(url, data, headers=None):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={{"Content-Type": "application/json", **(headers or {{}})}})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())

def enroll():
    if os.path.exists(CONF):
        return json.load(open(CONF))
    payload = {{"token": TOKEN, "hostname": socket.gethostname(), "ip": "127.0.0.1", "os": platform.platform(), "version": "0.1.0"}}
    data = post(BUHO_URL + "/api/agents/enroll", payload)
    with open(CONF, "w") as f: json.dump(data, f)
    return data

def loop():
    conf = enroll()
    while True:
        hb = {{"agent_id": conf["agent_id"], "status": "ONLINE", "metadata": {{"demo": True, "load": 0.33}}}}
        post(BUHO_URL + "/api/agents/heartbeat", hb, headers={{"X-Buho-Agent-Key": conf["agent_key"]}})
        print("heartbeat sent")
        time.sleep(15)

if __name__ == "__main__":
    loop()
EOF

cat > "$INSTALL_DIR/buho-agent.service" <<'EOF'
[Unit]
Description=Buho Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/buho-agent/agent.py
Restart=always
Environment=BUHO_URL={server_url}
Environment=BUHO_TOKEN={token}

[Install]
WantedBy=multi-user.target
EOF

if command -v systemctl >/dev/null 2>&1; then
  sudo cp "$INSTALL_DIR/buho-agent.service" /etc/systemd/system/buho-agent.service || true
  sudo systemctl daemon-reload || true
  sudo systemctl enable --now buho-agent || true
else
  echo "systemd no disponible. Ejecuta manualmente: BUHO_TOKEN=$TOKEN BUHO_URL=$BUHO_URL python3 /opt/buho-agent/agent.py"
fi

echo "Agente instalado y reportando"
'''
        response = HttpResponse(script, content_type='text/x-shellscript')
        response['Content-Disposition'] = 'attachment; filename="buho-agent-linux.sh"'
        return response


class AgentDownloadWindowsView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        token = request.GET.get('token', '')
        create_audit_log(request=request, actor=request.user, action='DOWNLOAD_AGENT', target_type='AgentDownload', metadata={'platform': 'windows'})
        server_url = request.build_absolute_uri('/').rstrip('/')
        script = f'''$BuhoUrl = "{server_url}"
$Token = "{token}"
Write-Host "Buho agent installer (placeholder)"
Write-Host "Download complete. Windows service installer en preparación."
Write-Host "For now run heartbeat stub manually against $BuhoUrl"
'''
        response = HttpResponse(script, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="buho-agent-windows.ps1"'
        return response
