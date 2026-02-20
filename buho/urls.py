from django.contrib import admin
from django.urls import include, path

from agents.views import ThreatsOverviewView
from ui.views import BuhoLoginView as LoginView, BuhoLogoutView, RegisterView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/login/', LoginView.as_view(), name='auth_login'),
    path('auth/register/', RegisterView.as_view(), name='auth_register'),
    path('', include(('ui.urls', 'ui'), namespace='ui')),
    path('', include(('accounts.urls', 'accounts'), namespace='accounts')),
    path('agents/', include(('agents.urls', 'agents'), namespace='agents')),
    path('threats/overview', ThreatsOverviewView.as_view(), name='threats_overview'),
    path('logout/', BuhoLogoutView.as_view(), name='logout'),
    path('api/', include('api.urls')),
]
