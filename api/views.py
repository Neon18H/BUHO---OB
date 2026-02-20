from datetime import timedelta
import secrets

from django.db import connection
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

from agents.incidents import evaluate_http_incidents, evaluate_log_incidents, evaluate_metric_incidents
from agents.health import calculate_agent_health, calculate_app_health
from agents.models import Agent, AgentCommand, AgentEnrollmentToken, AgentHeartbeat, DetectedApp, Incident, LogEntry, MetricPoint, NocturnalScanRun, ProcessSample, ThreatFinding
from agents.security import redact_payload, redact_text
from agents.threats import ingest_artifacts, ingest_findings
from audit.models import AuditLog
from buho.runtime import get_db_label, get_public_base_url
from soc.models import CorrelatedAlert, DetectionRule, SecurityEvent

from .serializers import (
    AgentCommandAckSerializer,
    AppsSerializer,
    DiscoverySerializer,
    EnrollSerializer,
    HeartbeatSerializer,
    LogsSerializer,
    MetricsSerializer,
    ProcessesSerializer,
    SecurityArtifactsSerializer,
    SecurityFindingsSerializer,
    NightScanCommandSerializer,
    QuarantineCommandSerializer,
    AgentCommandResultSerializer,
)


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
        return Response({'agent_id': agent.id, 'agent_key': raw_key, 'server_url': get_public_base_url(request)})


class HealthApiView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
        return Response({'ok': True, 'db': get_db_label()})


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
            sec_rows = []
            for item in serializer.validated_data['logs']:
                message = redact_text(item.get('message', ''))
                ts = item.get('ts') or timezone.now()
                rows.append(
                    LogEntry(
                        organization=agent.organization,
                        agent=agent,
                        level=item.get('level', LogEntry.Level.INFO),
                        source=item.get('source', 'agent'),
                        message=message,
                        ts=ts,
                        fields_json=redact_payload(item.get('fields') or {}),
                    )
                )
                message_low = message.lower()
                event_type = None
                severity = 'LOW'
                if 'failed password' in message_low or 'authentication failure' in message_low:
                    event_type, severity = 'auth_failure', 'MEDIUM'
                elif 'suspicious' in message_low or 'powershell -enc' in message_low:
                    event_type, severity = 'suspicious_cmdline', 'HIGH'
                elif 'yara' in message_low or 'malware' in message_low:
                    event_type, severity = 'yara_match', 'CRITICAL'
                if event_type:
                    sec_rows.append(SecurityEvent(organization=agent.organization, agent=agent, ts=ts, source=item.get('source', 'agent'), event_type=event_type, severity=severity, title=event_type.replace('_', ' ').title(), message=message, raw_json=item, tags=[event_type]))
            LogEntry.objects.bulk_create(rows)
            if sec_rows:
                SecurityEvent.objects.bulk_create(sec_rows)
        evaluate_log_incidents(agent.organization, agent)
        now = timezone.now()
        for rule in DetectionRule.objects.filter(organization=agent.organization, enabled=True):
            contains = (rule.query_json or {}).get('contains', '').lower()
            if not contains:
                continue
            window_start = now - timedelta(seconds=rule.window_seconds)
            matched = SecurityEvent.objects.filter(organization=agent.organization, ts__gte=window_start, message__icontains=contains)
            if matched.count() >= rule.threshold:
                alert = CorrelatedAlert.objects.create(organization=agent.organization, severity=rule.severity, title=f'Rule matched: {rule.name}', description=f'Threshold {rule.threshold} reached for {contains}', status=CorrelatedAlert.Status.OPEN)
                alert.linked_events.add(*matched[:50])

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


class NightScanCommandApiView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if request.user.role not in {'SUPERADMIN', 'SUPER_ADMIN', 'ORG_ADMIN'}:
            return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        serializer = NightScanCommandSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        org = request.user.organization
        agent = Agent.objects.filter(id=serializer.validated_data['agent_id'], organization=org).first()
        if not agent:
            return Response({'detail': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)
        payload = {
            'paths': serializer.validated_data.get('paths') or [],
            'exclusions': serializer.validated_data.get('exclusions') or [],
            'vt': bool(serializer.validated_data.get('vt', False)),
        }
        command = AgentCommand.objects.create(
            organization=org,
            agent=agent,
            command_type=AgentCommand.CommandType.NIGHT_SCAN,
            payload_json=payload,
            status=AgentCommand.Status.PENDING,
            issued_by=request.user,
        )
        return Response({'command_id': str(command.id)})


class QuarantineCommandApiView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if request.user.role not in {'SUPERADMIN', 'SUPER_ADMIN', 'ORG_ADMIN'}:
            return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        serializer = QuarantineCommandSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        org = request.user.organization
        agent = Agent.objects.filter(id=serializer.validated_data['agent_id'], organization=org).first()
        if not agent:
            return Response({'detail': 'Agent not found'}, status=status.HTTP_404_NOT_FOUND)
        command = AgentCommand.objects.create(
            organization=org,
            agent=agent,
            command_type=AgentCommand.CommandType.QUARANTINE_FILE,
            payload_json={
                'file_path': serializer.validated_data['file_path'],
                'method': serializer.validated_data.get('method', 'move'),
                'reason': serializer.validated_data.get('reason', ''),
            },
            status=AgentCommand.Status.PENDING,
            issued_by=request.user,
        )
        return Response({'command_id': str(command.id)})


class AgentCommandPollApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        commands = list(AgentCommand.objects.filter(
            organization=agent.organization,
            agent=agent,
            status=AgentCommand.Status.PENDING,
        ).order_by('created_at')[:10])
        if not commands:
            return Response({'commands': []})
        now = timezone.now()
        AgentCommand.objects.filter(id__in=[c.id for c in commands]).update(status=AgentCommand.Status.RUNNING, started_at=now)
        return Response({'commands': [{'id': str(c.id), 'type': c.command_type, 'payload': c.payload_json, 'created_at': c.created_at} for c in commands]})


class AgentCommandResultApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = AgentCommandResultSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        command = AgentCommand.objects.filter(id=data['command_id'], agent=agent, organization=agent.organization).first()
        if not command:
            return Response({'detail': 'Command not found'}, status=status.HTTP_404_NOT_FOUND)
        command.status = AgentCommand.Status.DONE if data['status'] == 'DONE' else AgentCommand.Status.FAILED
        command.finished_at = timezone.now()
        command.result_json = data.get('result') or {}
        command.error_text = data.get('error', '')
        command.save(update_fields=['status', 'finished_at', 'result_json', 'error_text', 'updated_at'])

        if command.command_type == AgentCommand.CommandType.NIGHT_SCAN and command.status == AgentCommand.Status.DONE:
            findings = (command.result_json or {}).get('findings') or []
            for finding in findings:
                sev = (finding.get('severity') or 'MED').upper()
                if sev not in {'LOW', 'MED', 'HIGH', 'CRIT'}:
                    sev = 'MED'
                created = ThreatFinding.objects.create(
                    organization=agent.organization,
                    agent=agent,
                    file_path=finding.get('file_path') or 'unknown',
                    file_hash_sha256=finding.get('file_hash_sha256') or None,
                    yara_rule=finding.get('yara_rule') or '',
                    yara_tags=finding.get('yara_tags') or [],
                    vt_score=finding.get('vt_score'),
                    vt_permalink=finding.get('vt_permalink') or None,
                    severity=sev,
                )
                Incident.objects.create(
                    organization=agent.organization,
                    agent=agent,
                    type=Incident.Type.MALWARE_SUSPECT,
                    severity='CRITICAL' if sev == 'CRIT' else ('HIGH' if sev == 'HIGH' else 'MEDIUM'),
                    status=Incident.Status.OPEN,
                    context_json={'message': f"YARA match {created.yara_rule} en {created.file_path}", 'finding_id': str(created.id)},
                )
        if command.command_type == AgentCommand.CommandType.QUARANTINE_FILE and command.status == AgentCommand.Status.DONE:
            fp = (command.payload_json or {}).get('file_path')
            ThreatFinding.objects.filter(organization=agent.organization, agent=agent, file_path=fp, status=ThreatFinding.Status.OPEN).update(
                action_taken=ThreatFinding.ActionTaken.QUARANTINED,
                quarantine_path=(command.result_json or {}).get('quarantine_path') or '',
            )
        return Response({'ok': True})


class AgentCommandAckApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        return Response({'ok': True})


class SecurityFindingsIngestApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = SecurityFindingsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        stored = ingest_findings(
            organization=agent.organization,
            agent=agent,
            findings=serializer.validated_data['findings'],
        )
        return Response({'ingested': stored})


class SecurityArtifactsIngestApiView(APIView, AgentAuthMixin):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        agent = self.get_agent_from_headers(request)
        if not agent:
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = SecurityArtifactsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        threshold = int((request.data or {}).get('vt_threshold') or 3)
        checked, hits = ingest_artifacts(
            organization=agent.organization,
            agent=agent,
            artifacts=serializer.validated_data['artifacts'],
            threshold=threshold,
        )
        return Response({'checked': checked, 'vt_hits': hits})
