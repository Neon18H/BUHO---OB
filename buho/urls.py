from django.contrib import admin
from django.urls import include, path

from agents.views import ThreatsOverviewView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(('ui.urls', 'ui'), namespace='ui')),
    path('', include(('accounts.urls', 'accounts'), namespace='accounts')),
    path('agents/', include(('agents.urls', 'agents'), namespace='agents')),
    path('threats/overview', ThreatsOverviewView.as_view(), name='threats_overview'),
    path('api/', include('api.urls')),
]
