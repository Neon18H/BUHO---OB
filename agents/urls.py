from django.urls import path

from .views import (
    AgentDetailTabView,
    AgentDetailView,
    AgentDownloadAgentPyView,
    AgentDownloadLinuxView,
    AgentDownloadRequirementsView,
    AgentDownloadWindowsView,
    AgentThreatsView,
    AgentsInstallView,
    AgentsOverviewView,
    ThreatsOverviewView,
    TokenCreateView,
    TokenRevokeView,
    TokensView,
)

app_name = 'agents'

urlpatterns = [
    path('overview/', AgentsOverviewView.as_view(), name='overview'),
    path('install/', AgentsInstallView.as_view(), name='install'),
    path('tokens/', TokensView.as_view(), name='tokens'),
    path('tokens/create/', TokenCreateView.as_view(), name='token_create'),
    path('tokens/<int:token_id>/revoke/', TokenRevokeView.as_view(), name='token_revoke'),
    path('download/linux.sh', AgentDownloadLinuxView.as_view(), name='download_linux'),
    path('download/agent.py', AgentDownloadAgentPyView.as_view(), name='download_agent_py'),
    path('download/requirements.txt', AgentDownloadRequirementsView.as_view(), name='download_requirements'),
    path('download/windows.ps1', AgentDownloadWindowsView.as_view(), name='download_windows'),
    path('threats/', ThreatsOverviewView.as_view(), name='threats_overview'),
    path('threats/overview/', ThreatsOverviewView.as_view(), name='threats_overview_legacy'),
    path('<int:agent_id>/threats/', AgentThreatsView.as_view(), name='agent_threats'),
    path('<int:agent_id>/tabs/<str:tab>/', AgentDetailTabView.as_view(), name='detail_tab'),

    path('<int:agent_id>/metrics/', AgentDetailTabView.as_view(), {'tab': 'metrics'}, name='detail_metrics'),
    path('<int:agent_id>/processes/', AgentDetailTabView.as_view(), {'tab': 'processes'}, name='detail_processes'),
    path('<int:agent_id>/apps/', AgentDetailTabView.as_view(), {'tab': 'apps'}, name='detail_apps'),
    path('<int:agent_id>/logs/', AgentDetailTabView.as_view(), {'tab': 'logs'}, name='detail_logs'),
    path('<int:agent_id>/health/', AgentDetailTabView.as_view(), {'tab': 'health'}, name='detail_health'),
    path('<int:agent_id>/night-ops/', AgentDetailTabView.as_view(), {'tab': 'night-ops'}, name='detail_night_ops'),

    path('<int:agent_id>/', AgentDetailView.as_view(), name='detail'),
]
