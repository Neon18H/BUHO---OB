import json
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login as auth_login
from django.contrib.auth.views import LoginView, LogoutView
from django.db.models import Avg, Max, Sum
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views import View

from accounts.forms import InitialRegistrationForm, OrganizationForm, OrganizationUserCreateForm, OrganizationUserUpdateForm
from accounts.models import Organization
from agents.models import Agent, Incident, LogEntry, MetricPoint, ProcessSample
from audit.models import AuditLog
from audit.utils import create_audit_log
from dashboards.models import Dashboard, DashboardWidget
from .permissions import RoleRequiredMixin

User = get_user_model()


class OrgScopedMixin:
    def get_org(self, request):
        return request.user.organization


def _sync_agent_status_for_org(org):
    if not org:
        return
    cutoff = timezone.now() - timedelta(seconds=getattr(settings, 'AGENT_OFFLINE_SECONDS', 90))
    Agent.objects.filter(organization=org, last_seen__lt=cutoff).exclude(status=Agent.Status.OFFLINE).update(status=Agent.Status.OFFLINE)
    Agent.objects.filter(organization=org, last_seen__gte=cutoff).exclude(status=Agent.Status.ONLINE).update(status=Agent.Status.ONLINE)


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


class RegisterView(View):
    template_name = 'registration/register.html'

    def dispatch(self, request, *args, **kwargs):
        if Organization.objects.exists():
            messages.info(request, 'El sistema ya fue inicializado. Inicia sesión para continuar.')
            return redirect('accounts:login')
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return render(request, self.template_name, {'form': InitialRegistrationForm()})

    def post(self, request):
        form = InitialRegistrationForm(request.POST)
        if not form.is_valid():
            messages.error(request, 'Corrige los errores para completar la inicialización.')
            return render(request, self.template_name, {'form': form})

        organization = Organization.objects.create(name=form.cleaned_data['organization_name'])
        user = form.save(commit=False)
        user.organization = organization
        user.role = User.Role.SUPERADMIN
        user.is_staff = True
        user.is_superuser = False
        user.save()

        AuditLog.objects.create(
            organization=organization,
            actor=user,
            action='SYSTEM_INIT',
            target_type='Organization',
            target_id=str(organization.id),
            metadata={'organization': organization.name},
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        create_audit_log(
            request=request,
            actor=user,
            action='REGISTER_SUPERADMIN',
            target_type='User',
            target_id=str(user.id),
            organization=organization,
            metadata={'username': user.username},
        )
        auth_login(request, user)
        messages.success(request, 'Organización inicial creada correctamente. ¡Bienvenido a Buho!')
        return redirect('ui:overview')


class OrganizationSwitchView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN'}

    def post(self, request):
        messages.info(request, 'El cambio manual de organización fue deshabilitado en modo multi-tenant por organización única.')
        return redirect(request.META.get('HTTP_REFERER', reverse('ui:overview')))


class OverviewView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        org = self.get_org(request)
        _sync_agent_status_for_org(org)
        now = timezone.now()
        offline_seconds = getattr(settings, 'AGENT_OFFLINE_SECONDS', 90)
        window_15m = now - timedelta(minutes=15)
        window_1h = now - timedelta(hours=1)

        if not org:
            return render(request, 'ui/overview.html', {'empty': True, 'selected_agent': None, 'agents': []})

        agents = Agent.objects.filter(organization=org)
        online_qs = agents.filter(last_seen__gte=now - timedelta(seconds=offline_seconds), status=Agent.Status.ONLINE)
        online_ids = list(online_qs.values_list('id', flat=True))

        cpu_avg = MetricPoint.objects.filter(organization=org, ts__gte=window_15m, name='cpu.percent').aggregate(v=Avg('value'))['v']
        ram_avg = MetricPoint.objects.filter(organization=org, ts__gte=window_15m, name='mem.percent').aggregate(v=Avg('value'))['v']
        disk_worst = MetricPoint.objects.filter(organization=org, ts__gte=window_15m, name='disk.root.used_percent').aggregate(v=Max('value'))['v']
        net_recv = MetricPoint.objects.filter(organization=org, ts__gte=window_15m, name='net.bytes_recv').aggregate(v=Sum('value'))['v'] or 0
        net_sent = MetricPoint.objects.filter(organization=org, ts__gte=window_15m, name='net.bytes_sent').aggregate(v=Sum('value'))['v'] or 0
        error_logs = LogEntry.objects.filter(organization=org, ts__gte=window_1h, level=LogEntry.Level.ERROR).count()

        selected_agent_id = request.GET.get('agent')
        selected_agent = agents.filter(id=selected_agent_id).first() if selected_agent_id else agents.first()
        series_points = MetricPoint.objects.none()
        cpu_values, ram_values, net_in, net_out, labels = [], [], [], [], []
        process_rows = []
        if selected_agent:
            series_points = MetricPoint.objects.filter(
                organization=org,
                agent=selected_agent,
                ts__gte=window_15m,
                name__in=['cpu.percent', 'mem.percent', 'net.bytes_recv', 'net.bytes_sent'],
            ).order_by('ts')
            grouped = {}
            for point in series_points:
                key = point.ts.replace(second=0, microsecond=0)
                grouped.setdefault(key, {})[point.name] = point.value
            for ts_key in sorted(grouped.keys()):
                labels.append(ts_key.strftime('%H:%M'))
                cpu_values.append(grouped[ts_key].get('cpu.percent', 0))
                ram_values.append(grouped[ts_key].get('mem.percent', 0))
                net_in.append(grouped[ts_key].get('net.bytes_recv', 0))
                net_out.append(grouped[ts_key].get('net.bytes_sent', 0))

            latest_ts = ProcessSample.objects.filter(organization=org, agent=selected_agent).aggregate(v=Max('ts'))['v']
            if latest_ts:
                process_rows = ProcessSample.objects.filter(organization=org, agent=selected_agent, ts=latest_ts).order_by('-cpu', '-mem')[:25]

        context = {
            'empty': MetricPoint.objects.filter(organization=org).count() == 0,
            'kpi_cards': [
                {'title': 'Agentes Online/Offline', 'value': f'{len(online_ids)}/{max(agents.count() - len(online_ids), 0)}', 'icon': 'bi-robot'},
                {'title': 'CPU Avg (15m)', 'value': f'{(cpu_avg or 0):.2f}%', 'icon': 'bi-cpu'},
                {'title': 'RAM Avg (15m)', 'value': f'{(ram_avg or 0):.2f}%', 'icon': 'bi-memory'},
                {'title': 'Disk Worst %', 'value': f'{(disk_worst or 0):.2f}%', 'icon': 'bi-device-hdd'},
                {'title': 'Network In/Out', 'value': f'{net_recv:.0f} / {net_sent:.0f}', 'icon': 'bi-diagram-3'},
                {'title': 'Error logs (1h)', 'value': error_logs, 'icon': 'bi-bug'},
            ],
            'agents': agents,
            'selected_agent': selected_agent,
            'cpu_labels': labels,
            'cpu_values': cpu_values,
            'ram_values': ram_values,
            'net_in': net_in,
            'net_out': net_out,
            'process_rows': process_rows,
            'recent_logs': LogEntry.objects.filter(organization=org).order_by('-ts')[:50],
            'recent_heartbeats': selected_agent.heartbeats.all()[:10] if selected_agent else [],
            'recent_incidents': Incident.objects.filter(organization=org).order_by('-last_seen')[:10],
        }
        return render(request, 'ui/overview.html', context)


class WidgetCreateView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST'}

    def post(self, request):
        org = request.user.organization
        if not org:
            messages.error(request, 'No organization selected.')
            return redirect('ui:overview')
        dashboard, _ = Dashboard.objects.get_or_create(organization=org, name='Default', defaults={'created_by': request.user, 'is_default': True})
        config_raw = request.POST.get('config_json', '{}').strip() or '{}'
        try:
            config_json = json.loads(config_raw)
        except json.JSONDecodeError:
            config_json = {'raw': config_raw}
        DashboardWidget.objects.create(
            dashboard=dashboard,
            type=request.POST.get('type', 'KPI'),
            title=request.POST.get('title', 'Nuevo widget'),
            config_json=config_json,
            position_json={},
        )
        messages.success(request, 'Widget agregado al dashboard.')
        return redirect('ui:overview')


class ServersListView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        org = self.get_org(request)
        return render(request, 'ui/servers_list.html', {'servers': Agent.objects.filter(organization=org) if org else []})


class ServerDetailView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request, server_id):
        org = self.get_org(request)
        server = get_object_or_404(Agent.objects.filter(organization=org), id=server_id)
        return render(request, 'ui/server_detail.html', {'server': server})


class AppsListView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        return render(request, 'ui/apps.html', {'apps': []})


class LogsExplorerView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST'}

    def get(self, request):
        level_filter = request.GET.get('level', '')
        search = request.GET.get('q', '').strip()
        org = self.get_org(request)
        logs = LogEntry.objects.filter(organization=org).order_by('-ts') if org else LogEntry.objects.none()
        if level_filter:
            logs = logs.filter(level=level_filter)
        if search:
            logs = logs.filter(message__icontains=search)
        return render(request, 'ui/logs.html', {'logs': logs[:200], 'level_filter': level_filter, 'search': search})


class AlertsView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST'}

    def get(self, request):
        org = self.get_org(request)
        alerts = Incident.objects.filter(organization=org).order_by('-last_seen') if org else Incident.objects.none()
        return render(request, 'ui/alerts.html', {'alerts': alerts})


class SettingsDashboardView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def get_user_queryset(self, request):
        return User.objects.filter(organization=request.user.organization).select_related('organization')

    def get_org_queryset(self, request):
        return Organization.objects.filter(id=request.user.organization_id)

    def get(self, request):
        context = {
            'users': self.get_user_queryset(request),
            'organizations': self.get_org_queryset(request),
            'create_form': OrganizationUserCreateForm(),
            'org_form': OrganizationForm(),
        }
        return render(request, 'ui/settings.html', context)


class UserCreateView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def post(self, request):
        form = OrganizationUserCreateForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.organization = request.user.organization
            user.save()
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
        if target.organization_id != request.user.organization_id:
            messages.error(request, 'Cannot edit a user from another organization.')
            return redirect('ui:settings')
        if request.user.role == User.Role.ORG_ADMIN and target.role == User.Role.SUPERADMIN:
            messages.error(request, 'ORG_ADMIN no puede modificar a un SUPERADMIN.')
            return redirect('ui:settings')

        form = OrganizationUserUpdateForm(request.POST, instance=target)

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
        if target.organization_id != request.user.organization_id:
            messages.error(request, 'Cannot deactivate a user from another organization.')
            return redirect('ui:settings')
        if request.user.role == User.Role.ORG_ADMIN and target.role == User.Role.SUPERADMIN:
            messages.error(request, 'ORG_ADMIN no puede desactivar a un SUPERADMIN.')
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


class UserResetPasswordView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def post(self, request, user_id):
        target = get_object_or_404(User, id=user_id)
        if target.organization_id != request.user.organization_id:
            messages.error(request, 'Cannot reset password for another organization.')
            return redirect('ui:settings')
        if request.user.role == User.Role.ORG_ADMIN and target.role == User.Role.SUPERADMIN:
            messages.error(request, 'ORG_ADMIN no puede resetear a un SUPERADMIN.')
            return redirect('ui:settings')
        temp_password = secrets.token_urlsafe(10)
        target.set_password(temp_password)
        target.save(update_fields=['password'])
        create_audit_log(
            request=request,
            actor=request.user,
            action='RESET_PASSWORD',
            target_type='User',
            target_id=str(target.id),
            organization=target.organization,
            metadata={'username': target.username},
        )
        messages.success(request, f'Password temporal para {target.username}: {temp_password}')
        return redirect('ui:settings')


class OrganizationUpdateView(RoleRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN'}

    def post(self, request, org_id):
        org = get_object_or_404(Organization, id=org_id)
        if org.id != request.user.organization_id:
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
