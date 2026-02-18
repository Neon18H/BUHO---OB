from django.urls import path

from .views import (
    AlertsView,
    AppsListView,
    LogsExplorerView,
    OrganizationUpdateView,
    OverviewView,
    ServerDetailView,
    ServersListView,
    SettingsDashboardView,
    UserCreateView,
    UserDeactivateView,
    UserResetPasswordView,
    UserUpdateView,
    WidgetCreateView,
)

app_name = 'ui'

urlpatterns = [
    path('', OverviewView.as_view(), name='overview'),
    path('servers/', ServersListView.as_view(), name='servers'),
    path('servers/<int:server_id>/', ServerDetailView.as_view(), name='server_detail'),
    path('apps/', AppsListView.as_view(), name='apps'),
    path('logs/', LogsExplorerView.as_view(), name='logs'),
    path('alerts/', AlertsView.as_view(), name='alerts'),
    path('widgets/create/', WidgetCreateView.as_view(), name='widget_create'),
    path('settings/', SettingsDashboardView.as_view(), name='settings'),
    path('settings/users/', SettingsDashboardView.as_view(), name='settings_users'),
    path('settings/users/create/', UserCreateView.as_view(), name='user_create'),
    path('settings/users/<int:user_id>/update/', UserUpdateView.as_view(), name='user_update'),
    path('settings/users/<int:user_id>/deactivate/', UserDeactivateView.as_view(), name='user_deactivate'),
    path('settings/users/<int:user_id>/reset-password/', UserResetPasswordView.as_view(), name='user_reset_password'),
    path('settings/organizations/<int:org_id>/update/', OrganizationUpdateView.as_view(), name='organization_update'),
]
