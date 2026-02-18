from django.urls import path

from .views import (
    AgentEnrollApiView,
    AgentHeartbeatApiView,
    AgentLogsIngestApiView,
    AgentMetricsIngestApiView,
    AgentProcessesIngestApiView,
)

urlpatterns = [
    path('agents/enroll', AgentEnrollApiView.as_view(), name='api_agents_enroll'),
    path('agents/heartbeat', AgentHeartbeatApiView.as_view(), name='api_agents_heartbeat'),
    path('ingest/metrics', AgentMetricsIngestApiView.as_view(), name='api_ingest_metrics'),
    path('ingest/processes', AgentProcessesIngestApiView.as_view(), name='api_ingest_processes'),
    path('ingest/logs', AgentLogsIngestApiView.as_view(), name='api_ingest_logs'),
]
