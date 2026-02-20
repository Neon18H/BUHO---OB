from django.contrib import admin
from django.contrib.auth.views import PasswordResetConfirmView
from django.urls import include, path

from agents.views import ThreatsOverviewView
from ui.views import AdminUsersView, BuhoLoginView as LoginView, BuhoLogoutView, RegisterView

handler500 = 'buho.views.handler500'

urlpatterns = [
    path('admin/users/', AdminUsersView.as_view(), name='auth_admin_users'),
    path('admin/', admin.site.urls),
    path('auth/login/', LoginView.as_view(), name='auth_login'),
    path('auth/register/', RegisterView.as_view(), name='auth_register'),
    path('auth/reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(template_name='auth/password_reset_confirm.html', success_url='/auth/login/'), name='auth_reset_confirm'),
    path('', include(('ui.urls', 'ui'), namespace='ui')),
    path('', include(('accounts.urls', 'accounts'), namespace='accounts')),
    path('agents/', include(('agents.urls', 'agents'), namespace='agents')),
    path('threats/overview', ThreatsOverviewView.as_view(), name='threats_overview'),
    path('logout/', BuhoLogoutView.as_view(), name='logout'),
    path('api/', include('api.urls')),
]
