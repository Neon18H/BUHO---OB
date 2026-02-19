import secrets

from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.incidents import evaluate_http_incidents, evaluate_log_incidents, evaluate_metric_incidents
from agents.health import calculate_agent_health, calculate_app_health
from agents.models import Agent, AgentEnrollmentToken, AgentHeartbeat, DetectedApp, LogEntry, MetricPoint, ProcessSample
from agents.security import redact_payload, redact_text
from audit.models import AuditLog

from .serializers import AppsSerializer, DiscoverySerializer, EnrollSerializer, HeartbeatSerializer, LogsSerializer, MetricsSerializer, ProcessesSerializer


class AgentAuthMixin:
    def get_agent_from_headers(self, request):
        agent_id = request.headers.get('X-Buho-Agent-Id')
        agent_key = request.headers.get('X-Buho-Agent-Key', '')
        if not agent_id or not agent_key:
            return None
        agent = Agent.objects.filter(id=agent_id).select_related('organization').first()
        if not agent or not agent.verify_key(agent_key):
            return None
        return agent


class AgentEnrollApiView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = EnrollSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token_value = serializer.validated_data['token']
        token = AgentEnrollmentToken.objects.filter(token=token_value, is_revoked=False).select_related('organization').first()
        if not token or token.is_expired:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        if token.is_used and not token.allow_multi_use:
            return Response({'detail': 'Token already used'}, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        agent, _ = Agent.objects.get_or_create(
            organization=token.organization,
            hostname=data['hostname'],
            defaults={
                'name': data.get('name') or data['hostname'],
                'ip_address': data['ip_address'],
                'os': data['os'],
                'arch': data.get('arch', 'x86_64'),
                'version': data['version'],
                'status': Agent.Status.ONLINE,
                'last_seen': timezone.now(),
            },
        )
        raw_key = secrets.token_urlsafe(32)
        agent.name = data.get('name') or agent.name
        agent.ip_address = data['ip_address']
        agent.os = data['os']
        agent.arch = data.get('arch', 'x86_64')
        agent.version = data['version']
        agent.agent_key_hash = Agent.hash_agent_key(raw_key)
        agent.status = Agent.Status.ONLINE
        agent.last_seen = timezone.now()
        agent.save()
        if not token.allow_multi_use:
            token.is_used = True
            token.save(update_fields=['is_used'])

        AuditLog.objects.create(
            organization=token.organization,
            actor=None,
            action='ENROLL_AGENT',
            target_type='Agent',
            target_id=str(agent.id),
            metadata={'hostname': agent.hostname},
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        return Response({'agent_id': agent.id, 'agent_key': raw_key, 'server_url': request.build_absolute_uri('/').rstrip('/')})


class AgentHeartbeatApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = HeartbeatSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        agent.last_seen = timezone.now()
        agent.status = serializer.validated_data.get('status', Agent.Status.ONLINE)
        agent.save(update_fields=['last_seen', 'status'])
        AgentHeartbeat.objects.create(agent=agent, status=agent.status, metadata_json=serializer.validated_data.get('metadata') or {})
        health, reasons = calculate_agent_health(agent)
        agent.health_score = health
        agent.save(update_fields=['health_score'])
        return Response({'ok': True, 'last_seen': agent.last_seen, 'health_score': health, 'reasons': reasons})


class AgentMetricsIngestApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = MetricsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ts = serializer.validated_data.get('ts') or timezone.now()
        rows = [
            MetricPoint(
                organization=agent.organization,
                agent=agent,
                name=item.get('name', 'unknown'),
                value=float(item.get('value', 0)),
                unit=item.get('unit', ''),
                ts=ts,
                labels_json=item.get('labels') or {},
            )
            for item in serializer.validated_data['metrics']
        ]
        MetricPoint.objects.bulk_create(rows)
        agent.last_seen = timezone.now()
        agent.status = Agent.Status.ONLINE
        evaluate_metric_incidents(agent.organization, agent)
        evaluate_http_incidents(agent.organization, agent)
        health, _ = calculate_agent_health(agent)
        agent.health_score = health
        agent.save(update_fields=['last_seen', 'status', 'health_score'])
        return Response({'ingested': len(rows), 'health_score': health})


class AgentProcessesIngestApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = ProcessesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ts = serializer.validated_data.get('ts') or timezone.now()
        rows = [
            ProcessSample(
                organization=agent.organization,
                agent=agent,
                pid=int(item.get('pid', 0)),
                name=item.get('name', 'unknown')[:255],
                cpu=float(item.get('cpu', 0)),
                mem=float(item.get('mem', 0)),
                user=item.get('user', '')[:255],
                cmdline_redacted=redact_text(item.get('cmdline', '')),
                ts=ts,
            )
            for item in serializer.validated_data['processes']
        ]
        ProcessSample.objects.bulk_create(rows)
        agent.last_seen = timezone.now()
        agent.status = Agent.Status.ONLINE
        agent.save(update_fields=['last_seen', 'status'])
        return Response({'ingested': len(rows)})


class AgentLogsIngestApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = LogsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            rows = []
            for item in serializer.validated_data['logs']:
                rows.append(
                    LogEntry(
                        organization=agent.organization,
                        agent=agent,
                        level=item.get('level', LogEntry.Level.INFO),
                        source=item.get('source', 'agent'),
                        message=redact_text(item.get('message', '')),
                        ts=item.get('ts') or timezone.now(),
                        fields_json=redact_payload(item.get('fields') or {}),
                    )
                )
            LogEntry.objects.bulk_create(rows)
        evaluate_log_incidents(agent.organization, agent)
        agent.last_seen = timezone.now()
        agent.status = Agent.Status.ONLINE
        health, _ = calculate_agent_health(agent)
        agent.health_score = health
        agent.save(update_fields=['last_seen', 'status', 'health_score'])
        return Response({'ingested': len(rows), 'health_score': health})


class AgentAppsIngestApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = AppsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ts = serializer.validated_data.get('ts') or timezone.now()
        for item in serializer.validated_data['apps']:
            defaults = {
                'kind': item.get('kind', 'unknown')[:64],
                'ports_json': item.get('ports') or [],
                'metadata_json': redact_payload(item.get('metadata') or {}),
                'last_seen': ts,
            }
            DetectedApp.objects.update_or_create(
                organization=agent.organization,
                agent=agent,
                name=(item.get('name') or 'unknown')[:120],
                pid=item.get('pid') or None,
                defaults=defaults,
            )
        return Response({'ingested': len(serializer.validated_data['apps'])})


class AgentDiscoveryIngestApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = DiscoverySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ts = serializer.validated_data.get('ts') or timezone.now()
        tags = serializer.validated_data.get('tags') or []
        agent.provider = serializer.validated_data.get('provider') or agent.provider
        agent.environment = serializer.validated_data.get('environment') or agent.environment
        agent.tags_json = tags
        agent.region = serializer.validated_data.get('region', agent.region)
        merged_meta = agent.cloud_metadata_json or {}
        merged_meta.update(serializer.validated_data.get('cloud_metadata') or {})
        merged_meta['hints'] = serializer.validated_data.get('hints') or {}
        agent.cloud_metadata_json = merged_meta
        agent.last_seen = timezone.now()
        agent.save(update_fields=['provider', 'environment', 'tags_json', 'region', 'cloud_metadata_json', 'last_seen'])

        for item in serializer.validated_data.get('apps') or []:
            defaults = {
                'kind': item.get('kind', 'unknown')[:64],
                'runtime': (item.get('runtime') or '')[:64],
                'framework': (item.get('framework') or '')[:64],
                'server': (item.get('server') or '')[:64],
                'ports_json': item.get('ports') or [],
                'process_hints_json': item.get('process_hints') or {},
                'metadata_json': redact_payload(item.get('metadata') or {}),
                'last_seen': ts,
            }
            app, _ = DetectedApp.objects.update_or_create(
                organization=agent.organization,
                agent=agent,
                name=(item.get('name') or 'unknown')[:120],
                pid=item.get('pid') or None,
                defaults=defaults,
            )
            app.app_health_score = calculate_app_health(app)
            app.save(update_fields=['app_health_score'])

        health, reasons = calculate_agent_health(agent)
        agent.health_score = health
        meta = agent.cloud_metadata_json or {}
        meta['health_reasons'] = reasons
        agent.cloud_metadata_json = meta
        agent.save(update_fields=['health_score', 'cloud_metadata_json'])
        return Response({'ok': True, 'health_score': health, 'apps': len(serializer.validated_data.get('apps') or [])})
