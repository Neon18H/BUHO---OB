from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
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


class AgentsListView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        agents = self.scoped_agents(request)
        create_audit_log(request=request, actor=request.user, action='VIEW_AGENT', target_type='AgentList', metadata={'count': agents.count()})
        return render(
            request,
            'agents/list.html',
            {
                'agents': agents,
                'can_manage_tokens': request.user.role in {'SUPERADMIN', 'ORG_ADMIN'},
            },
        )


class AgentDetailView(RoleRequiredMixin, AgentOrganizationMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request, agent_id):
        agent = get_object_or_404(self.scoped_agents(request), id=agent_id)
        create_audit_log(request=request, actor=request.user, action='VIEW_AGENT', target_type='Agent', target_id=str(agent.id))
        return render(request, 'agents/detail.html', {'agent': agent})


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
            messages.error(request, 'Invalid expiration selection.')
            return redirect('agents:tokens')

        org = self.scoped_organization(request)
        if org is None:
            messages.error(request, 'Select an organization scope first.')
            return redirect('agents:tokens')

        token = AgentEnrollmentToken.objects.create(
            organization=org,
            token=AgentEnrollmentToken.generate_secure_token(),
            expires_at=form.get_expires_at(),
            created_by=request.user,
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
        return redirect('agents:tokens')


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
