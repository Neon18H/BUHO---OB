from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from ui.permissions import RoleRequiredMixin
from .models import CorrelatedAlert, DetectionRule, SecurityEvent


class SocBaseView(RoleRequiredMixin, LoginRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get_org(self, request):
        return request.user.organization if request.user.organization_id else None


class SocOverviewView(SocBaseView):
    def get(self, request):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')

        since = timezone.now() - timedelta(hours=24)
        events = SecurityEvent.objects.filter(organization=org, ts__gte=since)
        alerts_open = CorrelatedAlert.objects.filter(organization=org, status=CorrelatedAlert.Status.OPEN).count()
        sev_by_hour = events.extra(select={'hour': "strftime('%%H', ts)"}).values('hour', 'severity').annotate(total=Count('id')).order_by('hour')
        top_types = events.values('event_type').annotate(total=Count('id')).order_by('-total')[:8]
        total_events = events.count()

        return render(request, 'soc/overview.html', {
            'events_24h': total_events,
            'alerts_open': alerts_open,
            'eps': round(total_events / 86400, 4),
            'top_agents': events.values('agent__hostname').annotate(total=Count('id')).order_by('-total')[:8],
            'top_severities': events.values('severity').annotate(total=Count('id')).order_by('-total'),
            'sev_labels': [f"{str(r['hour']).zfill(2)}:00" for r in sev_by_hour],
            'sev_values': [r['total'] for r in sev_by_hour],
            'type_labels': [r['event_type'] for r in top_types],
            'type_values': [r['total'] for r in top_types],
            'empty': total_events == 0,
        })


class SocEventsView(SocBaseView):
    def get(self, request):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')

        severity = request.GET.get('severity', '').strip()
        contains = request.GET.get('contains', '').strip()
        agent_id = request.GET.get('agent_id', '').strip()
        server_id = request.GET.get('server_id', '').strip()
        last_hours = int(request.GET.get('last_hours', '24') or 24)

        events = SecurityEvent.objects.filter(organization=org, ts__gte=timezone.now() - timedelta(hours=last_hours)).select_related('agent').order_by('-ts')
        if severity:
            events = events.filter(severity=severity)
        if contains:
            events = events.filter(message__icontains=contains)
        if agent_id:
            events = events.filter(agent_id=agent_id)
        if server_id:
            events = events.filter(agent_id=server_id)

        paginator = Paginator(events, 50)
        page_obj = paginator.get_page(request.GET.get('page'))
        return render(request, 'soc/events.html', {
            'page_obj': page_obj,
            'events': page_obj.object_list,
            'severity': severity,
            'contains': contains,
            'agent_id': agent_id,
            'server_id': server_id,
            'last_hours': last_hours,
            'empty': not page_obj.object_list,
        })


class SocAlertsView(SocBaseView):
    def get(self, request):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')
        alerts = CorrelatedAlert.objects.filter(organization=org).order_by('-created_at')[:200]
        return render(request, 'soc/alerts.html', {'alerts': alerts, 'empty': not alerts})

    def post(self, request):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')
        alert = get_object_or_404(CorrelatedAlert, organization=org, id=request.POST.get('alert_id'))
        if request.POST.get('action') in {'ACK', 'RESOLVED'}:
            alert.status = request.POST.get('action')
            alert.save(update_fields=['status'])
        return redirect('soc:alerts')


class SocRulesView(SocBaseView):
    def get(self, request):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')
        return render(request, 'soc/rules.html', {'rules': DetectionRule.objects.filter(organization=org).order_by('name')})

    def post(self, request):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')
        if request.user.role not in {'SUPERADMIN', 'ORG_ADMIN'}:
            return redirect('soc:rules')
        DetectionRule.objects.create(
            organization=org,
            name=request.POST.get('name', 'New rule'),
            severity=request.POST.get('severity', 'MEDIUM'),
            threshold=int(request.POST.get('threshold', 1) or 1),
            window_seconds=int(request.POST.get('window_seconds', 300) or 300),
            query_json={'contains': request.POST.get('contains', '')},
        )
        return redirect('soc:rules')
