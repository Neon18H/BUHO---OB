from django.urls import path
from .views import SocAlertsView, SocEventsView, SocOverviewView, SocRulesView

app_name = 'soc'

urlpatterns = [
    path('overview/', SocOverviewView.as_view(), name='overview'),
    path('events/', SocEventsView.as_view(), name='events'),
    path('alerts/', SocAlertsView.as_view(), name='alerts'),
    path('rules/', SocRulesView.as_view(), name='rules'),
]
