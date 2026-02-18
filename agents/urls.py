from django.urls import path

from .views import (
    AgentDetailView,
    AgentDownloadLinuxPyView,
    AgentDownloadLinuxView,
    AgentDownloadWindowsView,
    AgentsInstallView,
    AgentsOverviewView,
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
    path('download/linux.py', AgentDownloadLinuxPyView.as_view(), name='download_linux_py'),
    path('download/windows.ps1', AgentDownloadWindowsView.as_view(), name='download_windows'),
    path('<int:agent_id>/', AgentDetailView.as_view(), name='detail'),
]
