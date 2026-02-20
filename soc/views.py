from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views import View

from ui.permissions import RoleRequiredMixin
from .models import CorrelatedAlert, DetectionRule, SecurityEvent


class SocBaseView(RoleRequiredMixin, LoginRequiredMixin, View):
    allowed_roles = {'SUPERADMIN', 'ORG_ADMIN', 'ANALYST', 'VIEWER'}

    def get_org(self, request):
        if not request.user.organization_id:
            return None
        return request.user.organization


class SocOverviewView(SocBaseView):
    def get(self, request):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')
        since = timezone.now() - timedelta(hours=24)
        events = SecurityEvent.objects.filter(organization=org, ts__gte=since)
        return render(request, 'soc/overview.html', {
            'events_24h': events.count(),
            'eps': round(events.count() / 86400, 4),
            'top_agents': events.values('agent__hostname').annotate(total=Count('id')).order_by('-total')[:8],
            'top_severities': events.values('severity').annotate(total=Count('id')).order_by('-total'),
        })


class SocEventsView(SocBaseView):
    def get(self, request):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')
        q = request.GET.get('q', '')
        severity = request.GET.get('severity', '')
        events = SecurityEvent.objects.filter(organization=org).order_by('-ts')
        if q:
            events = events.filter(message__icontains=q)
        if severity:
            events = events.filter(severity=severity)
        return render(request, 'soc/events.html', {'events': events[:300], 'q': q, 'severity': severity})


class SocAlertsView(SocBaseView):
    def get(self, request):
        org = self.get_org(request)
        if not org:
            return redirect('auth_register')
        return render(request, 'soc/alerts.html', {'alerts': CorrelatedAlert.objects.filter(organization=org).order_by('-created_at')[:200]})


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
