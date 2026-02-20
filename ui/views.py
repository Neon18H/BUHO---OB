import json
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login as auth_login
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView, LogoutView
from django.db.models import Avg, Count, Max, Q, Sum
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views import View

from accounts.forms import InitialRegistrationForm, OrganizationForm, OrganizationUserCreateForm, OrganizationUserUpdateForm
from accounts.models import Organization
from agents.models import Agent, AgentCommand, DetectedApp, Incident, LogEntry, MetricPoint, ProcessSample, SecurityFinding
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
    now = timezone.now()
    offline_seconds = getattr(settings, 'AGENT_OFFLINE_SECONDS', 90)
    degraded_seconds = getattr(settings, 'AGENT_DEGRADED_SECONDS', 30)
    offline_cutoff = now - timedelta(seconds=offline_seconds)
    degraded_cutoff = now - timedelta(seconds=degraded_seconds)
    Agent.objects.filter(organization=org, last_seen__lt=offline_cutoff).exclude(status=Agent.Status.OFFLINE).update(status=Agent.Status.OFFLINE)
    Agent.objects.filter(organization=org, last_seen__lt=degraded_cutoff, last_seen__gte=offline_cutoff).exclude(status=Agent.Status.DEGRADED).update(status=Agent.Status.DEGRADED)
    Agent.objects.filter(organization=org, last_seen__gte=degraded_cutoff).exclude(status=Agent.Status.ONLINE).update(status=Agent.Status.ONLINE)


class BuhoLoginView(LoginView):
    template_name = 'auth/login.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        create_audit_log(request=self.request, actor=self.request.user, action='LOGIN', target_type='User', target_id=str(self.request.user.id))
        return response


class BuhoLogoutView(LogoutView):
    http_method_names = ['post', 'options']
    next_page = reverse_lazy('accounts:login')

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            create_audit_log(request=request, actor=request.user, action='LOGOUT', target_type='User', target_id=str(request.user.id))
        return super().dispatch(request, *args, **kwargs)


class RegisterView(View):
    template_name = 'auth/register.html'

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

    def _filtered_scope(self, request, org):
        provider = request.GET.get('provider', '')
        server_id = request.GET.get('server', '')
        app_id = request.GET.get('app', '')
        time_range = request.GET.get('time_range', '24h')
        minutes_map = {'15m': 15, '1h': 60, '24h': 1440, '7d': 10080}
        window_minutes = minutes_map.get(time_range, 1440)
        since = timezone.now() - timedelta(minutes=window_minutes)

        agents = Agent.objects.filter(organization=org)
        if provider:
            agents = agents.filter(provider=provider)
        if server_id:
            agents = agents.filter(id=server_id)

        apps = DetectedApp.objects.filter(organization=org)
        if app_id:
            apps = apps.filter(id=app_id)
        if provider:
            apps = apps.filter(agent__provider=provider)
        if server_id:
            apps = apps.filter(agent_id=server_id)

        logs = LogEntry.objects.filter(organization=org, ts__gte=since)
        incidents = Incident.objects.filter(organization=org, last_seen__gte=since)
        if provider:
            logs = logs.filter(agent__provider=provider)
            incidents = incidents.filter(agent__provider=provider)
        if server_id:
            logs = logs.filter(agent_id=server_id)
            incidents = incidents.filter(agent_id=server_id)
        if app_id:
            target_app = DetectedApp.objects.filter(organization=org, id=app_id).first()
            if target_app:
                logs = logs.filter(Q(source__icontains=target_app.name) | Q(fields_json__app_hint=target_app.name))

        return {
            'time_range': time_range,
            'since': since,
            'agents': agents,
            'apps': apps,
            'logs': logs,
            'incidents': incidents,
            'provider': provider,
            'server_id': server_id,
            'app_id': app_id,
        }

    def _overview_context(self, request, org):
        scope = self._filtered_scope(request, org)
        agents = scope['agents']
        logs = scope['logs']
        incidents = scope['incidents']
        now = timezone.now()
        week_ago = now - timedelta(days=7)
        selected_agent = agents.first()

        cpu_avg = MetricPoint.objects.filter(organization=org, ts__gte=scope['since'], name='cpu.percent')
        ram_avg = MetricPoint.objects.filter(organization=org, ts__gte=scope['since'], name='mem.percent')
        if scope['provider']:
            cpu_avg = cpu_avg.filter(agent__provider=scope['provider'])
            ram_avg = ram_avg.filter(agent__provider=scope['provider'])
        if scope['server_id']:
            cpu_avg = cpu_avg.filter(agent_id=scope['server_id'])
            ram_avg = ram_avg.filter(agent_id=scope['server_id'])

        metrics_series = MetricPoint.objects.filter(
            organization=org,
            ts__gte=scope['since'],
            name__in=['cpu.percent', 'mem.percent'],
        ).order_by('ts')
        if scope['provider']:
            metrics_series = metrics_series.filter(agent__provider=scope['provider'])
        if scope['server_id']:
            metrics_series = metrics_series.filter(agent_id=scope['server_id'])

        labels, cpu_values, ram_values = [], [], []
        grouped = {}
        for point in metrics_series:
            key = point.ts.replace(second=0, microsecond=0)
            grouped.setdefault(key, {'cpu.percent': [], 'mem.percent': []})
            grouped[key][point.name].append(point.value)
        for ts_key in sorted(grouped.keys()):
            labels.append(ts_key.strftime('%H:%M'))
            cpu_values.append(sum(grouped[ts_key]['cpu.percent']) / max(len(grouped[ts_key]['cpu.percent']), 1))
            ram_values.append(sum(grouped[ts_key]['mem.percent']) / max(len(grouped[ts_key]['mem.percent']), 1))

        logs_by_severity = {lvl: logs.filter(level=lvl).count() for lvl, _ in LogEntry.Level.choices}
        alerts_by_type = list(incidents.values('type').annotate(total=Count('id')).order_by('-total')[:8])
        top_apps = (
            scope['apps']
            .annotate(error_count=Count('agent__log_entries', filter=Q(agent__log_entries__level=LogEntry.Level.ERROR)))
            .order_by('-error_count', 'name')[:10]
        )

        return {
            'scope': scope,
            'kpis': {
                'online': agents.filter(status=Agent.Status.ONLINE).count(),
                'offline': agents.filter(status=Agent.Status.OFFLINE).count(),
                'servers': agents.count(),
                'apps': scope['apps'].count(),
                'logs_24h': LogEntry.objects.filter(organization=org, ts__gte=now - timedelta(hours=24)).count(),
                'alerts_24h': Incident.objects.filter(organization=org, last_seen__gte=now - timedelta(hours=24)).count(),
                'threats_7d': SecurityFinding.objects.filter(organization=org, last_seen__gte=week_ago).count(),
                'cpu_avg': round(cpu_avg.aggregate(v=Avg('value'))['v'] or 0, 2),
                'ram_avg': round(ram_avg.aggregate(v=Avg('value'))['v'] or 0, 2),
            },
            'charts': {
                'labels': labels,
                'cpu_values': cpu_values,
                'ram_values': ram_values,
                'logs_labels': list(logs_by_severity.keys()),
                'logs_values': list(logs_by_severity.values()),
                'alerts_labels': [row['type'] for row in alerts_by_type],
                'alerts_values': [row['total'] for row in alerts_by_type],
            },
            'top_apps': top_apps,
            'providers': Agent.Provider.choices,
            'servers': Agent.objects.filter(organization=org).order_by('hostname'),
            'all_apps': DetectedApp.objects.filter(organization=org).order_by('name')[:200],
        }

    def get(self, request):
        org = self.get_org(request)
        _sync_agent_status_for_org(org)
        if not org:
            return render(request, 'ui/overview.html', {'empty': True, 'providers': Agent.Provider.choices})

        context = self._overview_context(request, org)
        context['empty'] = context['kpis']['servers'] == 0
        context['filters'] = {
            'provider': context['scope']['provider'],
            'server': context['scope']['server_id'],
            'app': context['scope']['app_id'],
            'time_range': context['scope']['time_range'],
        }
        return render(request, 'ui/overview.html', context)


class OverviewKpiPartialView(OverviewView):
    def get(self, request):
        context = self._overview_context(request, self.get_org(request))
        return render(request, 'ui/partials/overview_kpis.html', context)


class OverviewChartsPartialView(OverviewView):
    def get(self, request):
        context = self._overview_context(request, self.get_org(request))
        return render(request, 'ui/partials/overview_charts.html', context)


class OverviewTablesPartialView(OverviewView):
    def get(self, request):
        context = self._overview_context(request, self.get_org(request))
        return render(request, 'ui/partials/overview_tables.html', context)


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
        provider = request.GET.get('provider', '')
        status = request.GET.get('status', '')
        servers = Agent.objects.filter(organization=org) if org else Agent.objects.none()
        if provider:
            servers = servers.filter(provider=provider)
        if status:
            servers = servers.filter(status=status)
        return render(request, 'ui/servers_list.html', {'servers': servers, 'filters': {'provider': provider, 'status': status}})


class ServerDetailView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request, server_id):
        org = self.get_org(request)
        if not org:
            messages.info(request, 'Primero completa el onboarding de tu organización.')
            return redirect('auth_register')

        server = get_object_or_404(Agent, pk=server_id, organization=org)
        latest_metric = MetricPoint.objects.filter(agent=server).order_by('-ts').first()
        latest_log = LogEntry.objects.filter(agent=server).order_by('-ts').first()
        latest_process = ProcessSample.objects.filter(agent=server).order_by('-ts').first()
        server_tabs = ['metrics', 'processes', 'apps', 'logs', 'health', 'night-ops']
        return render(
            request,
            'ui/server_detail.html',
            {
                'server': server,
                'server_tabs': server_tabs,
                'latest_metric': latest_metric,
                'latest_log': latest_log,
                'latest_process': latest_process,
                'no_data_message': 'Waiting for agent telemetry',
            },
        )




class ServerDetailTabView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request, server_id, tab):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')
        server = get_object_or_404(Agent, pk=server_id, organization=org)
        templates = {
            'metrics': 'ui/partials/server_metrics.html',
            'processes': 'ui/partials/server_processes.html',
            'apps': 'ui/partials/server_apps.html',
            'logs': 'ui/partials/server_logs.html',
            'health': 'ui/partials/server_health.html',
            'night-ops': 'ui/partials/server_night_ops.html',
        }
        template = templates.get(tab)
        if not template:
            return redirect('ui:server_detail', server_id=server.id)
        context = {'server': server}
        if tab == 'metrics':
            context['metrics'] = MetricPoint.objects.filter(agent=server).order_by('-ts')[:120]
        elif tab == 'processes':
            latest = ProcessSample.objects.filter(agent=server).order_by('-ts').values_list('ts', flat=True).first()
            context['processes'] = ProcessSample.objects.filter(agent=server, ts=latest).order_by('-cpu', '-mem')[:100] if latest else []
        elif tab == 'apps':
            context['apps'] = DetectedApp.objects.filter(agent=server).order_by('-last_seen')[:100]
        elif tab == 'logs':
            context['logs'] = LogEntry.objects.filter(agent=server).order_by('-ts')[:150]
        elif tab == 'night-ops':
            context['latest_nocturnal_run'] = AgentCommand.objects.filter(agent=server, command_type=AgentCommand.CommandType.NIGHT_SCAN).order_by('-created_at').first()
            context['recent_findings'] = SecurityFinding.objects.filter(agent=server).order_by('-last_seen')[:60]
        return render(request, template, context)
class AppsListView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request):
        org = self.get_org(request)
        provider = request.GET.get('provider', '')
        env = request.GET.get('env', '')
        agent_id = request.GET.get('agent', '')
        apps = DetectedApp.objects.filter(organization=org).select_related('agent').order_by('-last_seen') if org else DetectedApp.objects.none()
        if provider:
            apps = apps.filter(agent__provider=provider)
        if env:
            apps = apps.filter(agent__environment=env)
        if agent_id:
            apps = apps.filter(agent_id=agent_id)
        return render(request, 'ui/apps.html', {'apps': apps[:200], 'providers': Agent.Provider.choices, 'envs': Agent.Environment.choices, 'agents': Agent.objects.filter(organization=org), 'filters': {'provider': provider, 'env': env, 'agent': agent_id}})


class AppDetailView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get(self, request, app_id):
        org = self.get_org(request)
        app = get_object_or_404(DetectedApp.objects.filter(organization=org).select_related('agent'), id=app_id)
        metrics = MetricPoint.objects.filter(organization=org, agent=app.agent, ts__gte=timezone.now() - timedelta(hours=1), name__in=['cpu.percent', 'mem.percent', 'http.requests.count', 'http.errors.count']).order_by('ts')
        labels, cpu_values, mem_values = [], [], []
        grouped = {}
        for point in metrics:
            key = point.ts.replace(second=0, microsecond=0)
            grouped.setdefault(key, {})[point.name] = grouped.setdefault(key, {}).get(point.name, 0) + point.value
        for ts_key in sorted(grouped.keys()):
            labels.append(ts_key.strftime('%H:%M'))
            cpu_values.append(grouped[ts_key].get('cpu.percent', 0))
            mem_values.append(grouped[ts_key].get('mem.percent', 0))
        app_logs = LogEntry.objects.filter(organization=org, agent=app.agent).filter(Q(source__icontains=app.name) | Q(fields_json__app_hint=app.name)).order_by('-ts')[:150]
        deploy_hint = f"Detectado: {app.agent.get_provider_display()} + {app.runtime or 'runtime-unknown'} + {app.framework or 'framework-unknown'}"
        return render(request, 'ui/app_detail.html', {'app': app, 'labels': labels, 'cpu_values': cpu_values, 'mem_values': mem_values, 'app_logs': app_logs, 'deploy_hint': deploy_hint})


class LogsExplorerView(RoleRequiredMixin, OrgScopedMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST'}

    def get(self, request):
        level_filter = request.GET.get('level', '')
        search = request.GET.get('contains', request.GET.get('q', '')).strip()
        provider = request.GET.get('provider', '')
        server_id = request.GET.get('server', '')
        app_id = request.GET.get('app', '')
        time_range = request.GET.get('time_range', '24h')
        org = self.get_org(request)
        logs = LogEntry.objects.filter(organization=org).order_by('-ts') if org else LogEntry.objects.none()
        if level_filter:
            logs = logs.filter(level=level_filter)
        if search:
            logs = logs.filter(message__icontains=search)
        if provider:
            logs = logs.filter(agent__provider=provider)
        if server_id:
            logs = logs.filter(agent_id=server_id)
        if app_id:
            app = DetectedApp.objects.filter(organization=org, id=app_id).first()
            if app:
                logs = logs.filter(Q(source__icontains=app.name) | Q(fields_json__app_hint=app.name))
        minutes = {'15m': 15, '1h': 60, '24h': 1440, '7d': 10080}.get(time_range, 1440)
        logs = logs.filter(ts__gte=timezone.now() - timedelta(minutes=minutes))
        if request.GET.get('export') == 'csv':
            import csv
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="buho_logs.csv"'
            writer = csv.writer(response)
            writer.writerow(['timestamp', 'level', 'source', 'agent', 'message'])
            for row in logs[:2000]:
                writer.writerow([row.ts.isoformat(), row.level, row.source, row.agent.hostname, row.message])
            return response
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


class AdminUsersView(SettingsDashboardView):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'VIEWER'}
    template_name = 'ui/admin_users.html'

    def get(self, request):
        context = {
            'users': self.get_user_queryset(request),
            'organizations': self.get_org_queryset(request),
            'create_form': OrganizationUserCreateForm(),
            'org_form': OrganizationForm(),
            'is_admin_users_page': True,
        }
        return render(request, self.template_name, context)


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
        uidb64 = urlsafe_base64_encode(force_bytes(target.pk))
        token = default_token_generator.make_token(target)
        reset_link = request.build_absolute_uri(reverse('auth_reset_confirm', kwargs={'uidb64': uidb64, 'token': token}))
        create_audit_log(
            request=request,
            actor=request.user,
            action='RESET_PASSWORD',
            target_type='User',
            target_id=str(target.id),
            organization=target.organization,
            metadata={'username': target.username},
        )
        messages.success(request, f'Link de reset para {target.username}: {reset_link}')
        return redirect('ui:admin_users')


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
