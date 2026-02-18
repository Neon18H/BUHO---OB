import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from django.utils import timezone

from accounts.models import Organization


class AgentEnrollmentToken(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='agent_tokens')
    token = models.CharField(max_length=128, unique=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    is_revoked = models.BooleanField(default=False)
    allow_multi_use = models.BooleanField(default=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    server_name_optional = models.CharField(max_length=120, blank=True)
    tags_json = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return f'Token {self.masked_token}'

    @property
    def masked_token(self):
        if len(self.token) < 8:
            return '****'
        return f'****{self.token[-4:]}'

    @property
    def is_expired(self):
        return timezone.now() >= self.expires_at

    @classmethod
    def generate_secure_token(cls):
        return secrets.token_urlsafe(32)


class Agent(models.Model):
    class Status(models.TextChoices):
        ONLINE = 'ONLINE', 'Online'
        OFFLINE = 'OFFLINE', 'Offline'
        DEGRADED = 'DEGRADED', 'Degraded'

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='agents')
    name = models.CharField(max_length=120)
    hostname = models.CharField(max_length=120)
    ip_address = models.GenericIPAddressField()
    os = models.CharField(max_length=120)
    arch = models.CharField(max_length=32, default='x86_64')
    version = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OFFLINE)
    last_seen = models.DateTimeField(null=True, blank=True)
    enrolled_at = models.DateTimeField(default=timezone.now)
    agent_key_hash = models.CharField(max_length=256, blank=True)

    class Meta:
        ordering = ('name',)
        unique_together = ('organization', 'hostname')

    def __str__(self):
        return self.name

    @staticmethod
    def hash_agent_key(raw_key: str):
        return make_password(raw_key)

    def verify_key(self, raw_key: str):
        return check_password(raw_key, self.agent_key_hash)


class AgentHeartbeat(models.Model):
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='heartbeats')
    ts = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, choices=Agent.Status.choices, default=Agent.Status.ONLINE)
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('-ts',)


class MetricPoint(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='metric_points')
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='metric_points')
    name = models.CharField(max_length=120)
    value = models.FloatField()
    unit = models.CharField(max_length=32, blank=True)
    ts = models.DateTimeField(default=timezone.now)
    labels_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('-ts',)
        indexes = [models.Index(fields=['organization', 'agent', 'name', 'ts'])]


class ProcessSample(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='process_samples')
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='process_samples')
    pid = models.IntegerField()
    name = models.CharField(max_length=255)
    cpu = models.FloatField(default=0.0)
    mem = models.FloatField(default=0.0)
    user = models.CharField(max_length=255, blank=True)
    cmdline_redacted = models.TextField(blank=True)
    ts = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ('-ts',)
        indexes = [models.Index(fields=['organization', 'agent', 'ts'])]


class LogEntry(models.Model):
    class Level(models.TextChoices):
        INFO = 'INFO', 'Info'
        WARN = 'WARN', 'Warn'
        ERROR = 'ERROR', 'Error'

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='log_entries')
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='log_entries')
    level = models.CharField(max_length=16, choices=Level.choices, default=Level.INFO)
    source = models.CharField(max_length=120, default='agent')
    message = models.TextField()
    ts = models.DateTimeField(default=timezone.now)
    fields_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('-ts',)
        indexes = [models.Index(fields=['organization', 'agent', 'level', 'ts'])]


class Incident(models.Model):
    class Type(models.TextChoices):
        CPU_SPIKE = 'CPU_SPIKE', 'CPU > 90% (3 samples)'
        DISK_CRITICAL = 'DISK_CRITICAL', 'Disk root > 90%'
        LOG_ERROR_FLOOD = 'LOG_ERROR_FLOOD', 'Error logs flood'

    class Severity(models.TextChoices):
        LOW = 'LOW', 'Low'
        MEDIUM = 'MEDIUM', 'Medium'
        HIGH = 'HIGH', 'High'
        CRITICAL = 'CRITICAL', 'Critical'

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Open'
        ACKED = 'ACKED', 'Acked'
        RESOLVED = 'RESOLVED', 'Resolved'

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='incidents')
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='incidents', null=True, blank=True)
    type = models.CharField(max_length=32, choices=Type.choices)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    started_at = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    context_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('-last_seen',)


class AgentDownload(models.Model):
    name = models.CharField(max_length=120)
    platform = models.CharField(max_length=30)
    version = models.CharField(max_length=50, default='demo')
    created_at = models.DateTimeField(auto_now_add=True)
