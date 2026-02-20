from django.urls import path

from .views import (
    AgentAppsIngestApiView,
    AgentCommandAckApiView,
    AgentCommandPollApiView,
    AgentCommandResultApiView,
    NightScanCommandApiView,
    QuarantineCommandApiView,
    AgentDiscoveryIngestApiView,
    AgentEnrollApiView,
    AgentHeartbeatApiView,
    AgentLogsIngestApiView,
    AgentMetricsIngestApiView,
    AgentProcessesIngestApiView,
    HealthApiView,
    SecurityArtifactsIngestApiView,
    SecurityFindingsIngestApiView,
)

urlpatterns = [
    path('health', HealthApiView.as_view(), name='api_health'),
    path('agents/enroll', AgentEnrollApiView.as_view(), name='api_agents_enroll'),
    path('agents/heartbeat', AgentHeartbeatApiView.as_view(), name='api_agents_heartbeat'),
    path('agent/commands/night-scan', NightScanCommandApiView.as_view(), name='api_agent_commands_night_scan'),
    path('agent/commands/quarantine', QuarantineCommandApiView.as_view(), name='api_agent_commands_quarantine'),
    path('agent/commands/poll', AgentCommandPollApiView.as_view(), name='api_agent_commands_poll'),
    path('agent/commands/result', AgentCommandResultApiView.as_view(), name='api_agent_commands_result'),
    path('agent/commands/ack', AgentCommandAckApiView.as_view(), name='api_agent_commands_ack'),
    path('ingest/metrics', AgentMetricsIngestApiView.as_view(), name='api_ingest_metrics'),
    path('ingest/processes', AgentProcessesIngestApiView.as_view(), name='api_ingest_processes'),
    path('ingest/logs', AgentLogsIngestApiView.as_view(), name='api_ingest_logs'),
    path('ingest/apps', AgentAppsIngestApiView.as_view(), name='api_ingest_apps'),
    path('ingest/discovery', AgentDiscoveryIngestApiView.as_view(), name='api_ingest_discovery'),
    path('ingest/security/findings', SecurityFindingsIngestApiView.as_view(), name='api_ingest_security_findings'),
    path('ingest/security/artifacts', SecurityArtifactsIngestApiView.as_view(), name='api_ingest_security_artifacts'),
]
