from django.urls import path

from .views import AgentDetailView, AgentsListView, TokenCreateView, TokenRevokeView, TokensView

app_name = 'agents'

urlpatterns = [
    path('', AgentsListView.as_view(), name='list'),
    path('tokens/', TokensView.as_view(), name='tokens'),
    path('tokens/create/', TokenCreateView.as_view(), name='token_create'),
    path('tokens/<int:token_id>/revoke/', TokenRevokeView.as_view(), name='token_revoke'),
    path('<int:agent_id>/', AgentDetailView.as_view(), name='detail'),
]
