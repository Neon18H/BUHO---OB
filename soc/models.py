from django.db import models
from accounts.models import Organization
from agents.models import Agent


class SecurityEvent(models.Model):
    class Severity(models.TextChoices):
        LOW = 'LOW', 'Low'
        MEDIUM = 'MEDIUM', 'Medium'
        HIGH = 'HIGH', 'High'
        CRITICAL = 'CRITICAL', 'Critical'

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='security_events')
    agent = models.ForeignKey(Agent, on_delete=models.SET_NULL, null=True, blank=True, related_name='security_events')
    ts = models.DateTimeField(db_index=True)
    source = models.CharField(max_length=64)
    event_type = models.CharField(max_length=64)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.LOW)
    title = models.CharField(max_length=180)
    message = models.TextField(blank=True)
    raw_json = models.JSONField(default=dict, blank=True)
    tags = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=16, default='OPEN')


class DetectionRule(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='detection_rules')
    name = models.CharField(max_length=120)
    enabled = models.BooleanField(default=True)
    query_json = models.JSONField(default=dict, blank=True)
    threshold = models.PositiveIntegerField(default=1)
    window_seconds = models.PositiveIntegerField(default=300)
    severity = models.CharField(max_length=16, default='MEDIUM')
    action = models.CharField(max_length=32, default='create_alert')


class CorrelatedAlert(models.Model):
    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Open'
        ACK = 'ACK', 'Ack'
        RESOLVED = 'RESOLVED', 'Resolved'

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='correlated_alerts')
    created_at = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=16)
    title = models.CharField(max_length=180)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    linked_events = models.ManyToManyField(SecurityEvent, blank=True, related_name='alerts')
