from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView, LogoutView
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.views import View

from accounts.forms import OrganizationForm, UserCreateForm, UserUpdateForm
from accounts.models import Organization
from audit.models import AuditLog
from audit.utils import create_audit_log
from .demo_data import get_alerts, get_apps, get_logs, get_servers
from agents.models import Agent
from .permissions import RoleRequiredMixin

User = get_user_model()


class BuhoLoginView(LoginView):
    template_name = 'registration/login.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        create_audit_log(request=self.request, actor=self.request.user, action='LOGIN', target_type='User', target_id=str(self.request.user.id))
        return response


class BuhoLogoutView(LogoutView):
    next_page = reverse_lazy('accounts:login')

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            create_audit_log(request=request, actor=request.user, action='LOGOUT', target_type='User', target_id=str(request.user.id))
        return super().dispatch(request, *args, **kwargs)


class OrganizationSwitchView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN'}

    def post(self, request):
        org_id = request.POST.get('organization_id')
        if org_id and Organization.objects.filter(id=org_id).exists():
            request.session['active_org_id'] = int(org_id)
            messages.success(request, 'Organization scope updated.')
        return redirect(request.META.get('HTTP_REFERER', reverse('ui:overview')))


class OverviewView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        logs = AuditLog.objects.all()
        if request.user.role != 'SUPERADMIN':
            logs = logs.filter(Q(organization=request.user.organization) | Q(organization__isnull=True))
        context = {
            'kpis': {
                'agents_online': Agent.objects.filter(status='ONLINE').count(),
                'active_alerts': 6,
                'errors_24h': 132,
                'monitored_servers': Agent.objects.count() or 24,
            },
            'events': logs[:10],
            'chart_labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            'chart_values': [12, 19, 8, 15, 21, 17, 14],
        }
        return render(request, 'ui/overview.html', context)


class ServersListView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        return render(request, 'ui/servers_list.html', {'servers': get_servers()})


class ServerDetailView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request, server_id):
        server = next((s for s in get_servers() if s['id'] == server_id), None)
        if not server:
            return redirect('ui:servers')
        return render(request, 'ui/server_detail.html', {'server': server})


class AppsListView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        return render(request, 'ui/apps.html', {'apps': get_apps()})


class LogsExplorerView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST'}

    def get(self, request):
        level_filter = request.GET.get('level', '')
        search = request.GET.get('q', '').strip().lower()
        logs = get_logs()
        if level_filter:
            logs = [entry for entry in logs if entry['level'] == level_filter]
        if search:
            logs = [entry for entry in logs if search in entry['message'].lower() or search in entry['source'].lower()]
        return render(request, 'ui/logs.html', {'logs': logs, 'level_filter': level_filter, 'search': search})


class AlertsView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST'}

    def get(self, request):
        return render(request, 'ui/alerts.html', {'alerts': get_alerts()})


class SettingsDashboardView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def get_user_queryset(self, request):
        qs = User.objects.all().select_related('organization')
        if request.user.role != 'SUPERADMIN':
            qs = qs.filter(organization=request.user.organization)
        return qs

    def get_org_queryset(self, request):
        qs = Organization.objects.all()
        if request.user.role != 'SUPERADMIN':
            qs = qs.filter(id=request.user.organization_id)
        return qs

    def get(self, request):
        context = {
            'users': self.get_user_queryset(request),
            'organizations': self.get_org_queryset(request),
            'create_form': UserCreateForm(),
            'org_form': OrganizationForm(),
        }
        return render(request, 'ui/settings.html', context)


class UserCreateView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def post(self, request):
        form = UserCreateForm(request.POST)
        if request.user.role != 'SUPERADMIN':
            form.fields['organization'].queryset = Organization.objects.filter(id=request.user.organization_id)
        if form.is_valid():
            user = form.save()
            create_audit_log(
                request=request,
                actor=request.user,
                action='CREATE_USER',
                target_type='User',
                target_id=str(user.id),
                organization=user.organization,
                metadata={'username': user.username, 'role': user.role},
            )
            messages.success(request, f'User {user.username} created.')
        else:
            messages.error(request, f'Error creating user: {form.errors.as_text()}')
        return redirect('ui:settings')


class UserUpdateView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def post(self, request, user_id):
        target = get_object_or_404(User, id=user_id)
        if request.user.role != 'SUPERADMIN' and target.organization_id != request.user.organization_id:
            messages.error(request, 'Cannot edit a user from another organization.')
            return redirect('ui:settings')

        form = UserUpdateForm(request.POST, instance=target)
        if request.user.role != 'SUPERADMIN':
            form.fields['organization'].queryset = Organization.objects.filter(id=request.user.organization_id)

        if form.is_valid():
            updated = form.save()
            create_audit_log(
                request=request,
                actor=request.user,
                action='UPDATE_USER',
                target_type='User',
                target_id=str(updated.id),
                organization=updated.organization,
                metadata={'username': updated.username, 'role': updated.role, 'active': updated.is_active},
            )
            messages.success(request, f'User {updated.username} updated.')
        else:
            messages.error(request, f'Error updating user: {form.errors.as_text()}')
        return redirect('ui:settings')


class UserDeactivateView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def post(self, request, user_id):
        target = get_object_or_404(User, id=user_id)
        if request.user.role != 'SUPERADMIN' and target.organization_id != request.user.organization_id:
            messages.error(request, 'Cannot deactivate a user from another organization.')
            return redirect('ui:settings')
        target.is_active = False
        target.save(update_fields=['is_active'])
        create_audit_log(
            request=request,
            actor=request.user,
            action='DEACTIVATE_USER',
            target_type='User',
            target_id=str(target.id),
            organization=target.organization,
            metadata={'username': target.username, 'deactivated': True},
        )
        messages.success(request, f'User {target.username} deactivated.')
        return redirect('ui:settings')


class OrganizationUpdateView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def post(self, request, org_id):
        org = get_object_or_404(Organization, id=org_id)
        if request.user.role != 'SUPERADMIN' and org.id != request.user.organization_id:
            messages.error(request, 'Cannot modify another organization.')
            return redirect('ui:settings')
        form = OrganizationForm(request.POST, instance=org)
        if form.is_valid():
            form.save()
            create_audit_log(
                request=request,
                actor=request.user,
                action='UPDATE_ORGANIZATION',
                target_type='Organization',
                target_id=str(org.id),
                organization=org,
                metadata={'name': org.name, 'plan': org.plan},
            )
            messages.success(request, 'Organization updated.')
        else:
            messages.error(request, f'Error updating organization: {form.errors.as_text()}')
        return redirect('ui:settings')
