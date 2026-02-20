from django.contrib import admin
from django.urls import include, path

from agents.views import ThreatsOverviewView
from ui.views import BuhoLogoutView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(('ui.urls', 'ui'), namespace='ui')),
    path('auth/', include(('accounts.urls', 'accounts'), namespace='accounts')),
    path('logout/', BuhoLogoutView.as_view(), name='logout'),
    path('agents/', include(('agents.urls', 'agents'), namespace='agents')),
    path('threats/', ThreatsOverviewView.as_view(), name='threats'),
    path('threats/overview', ThreatsOverviewView.as_view(), name='threats_overview'),
    path('api/', include('api.urls')),
]
