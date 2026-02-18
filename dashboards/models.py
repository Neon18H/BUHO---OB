from django.conf import settings
from django.db import models

from accounts.models import Organization


class Dashboard(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='dashboards')
    name = models.CharField(max_length=120)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    is_default = models.BooleanField(default=False)

    class Meta:
        unique_together = ('organization', 'name')


class DashboardWidget(models.Model):
    dashboard = models.ForeignKey(Dashboard, on_delete=models.CASCADE, related_name='widgets')
    type = models.CharField(max_length=32)
    title = models.CharField(max_length=120)
    config_json = models.JSONField(default=dict, blank=True)
    position_json = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
