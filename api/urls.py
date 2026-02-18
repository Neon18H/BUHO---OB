from django.urls import path

from .views import AgentEnrollApiView, AgentHeartbeatApiView

urlpatterns = [
    path('agents/enroll', AgentEnrollApiView.as_view(), name='api_agents_enroll'),
    path('agents/heartbeat', AgentHeartbeatApiView.as_view(), name='api_agents_heartbeat'),
]
