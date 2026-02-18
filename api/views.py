import secrets

from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent, AgentEnrollmentToken, AgentHeartbeat
from audit.models import AuditLog


class AgentEnrollApiView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        token_value = request.data.get('token', '')
        token = AgentEnrollmentToken.objects.filter(token=token_value, is_revoked=False).select_related('organization').first()
        if not token or token.is_expired:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        if token.is_used and not token.allow_multi_use:
            return Response({'detail': 'Token already used'}, status=status.HTTP_400_BAD_REQUEST)

        hostname = request.data.get('hostname', 'unknown')
        agent, _ = Agent.objects.get_or_create(
            organization=token.organization,
            hostname=hostname,
            defaults={
                'name': hostname,
                'ip_address': request.data.get('ip', '127.0.0.1'),
                'os': request.data.get('os', 'linux'),
                'version': request.data.get('version', '0.1.0'),
                'status': Agent.Status.ONLINE,
                'last_seen': timezone.now(),
            },
        )
        raw_key = secrets.token_urlsafe(32)
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
            metadata={'hostname': hostname},
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )
        return Response({'agent_id': agent.id, 'agent_key': raw_key})


class AgentHeartbeatApiView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        key = request.headers.get('X-Buho-Agent-Key', '')
        agent_id = request.data.get('agent_id')
        agent = Agent.objects.filter(id=agent_id).first()
        if not agent or not agent.verify_key(key):
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        agent.last_seen = timezone.now()
        agent.status = request.data.get('status', Agent.Status.ONLINE)
        agent.save(update_fields=['last_seen', 'status'])
        AgentHeartbeat.objects.create(agent=agent, status=agent.status, metadata_json=request.data.get('metadata') or {})
        return Response({'ok': True, 'last_seen': agent.last_seen})
