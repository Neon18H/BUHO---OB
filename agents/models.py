import hashlib
import secrets

from django.conf import settings
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
    agent_key_hash = models.CharField(max_length=128, blank=True)

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name

    @staticmethod
    def hash_agent_key(raw_key: str):
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def verify_key(self, raw_key: str):
        return self.agent_key_hash == self.hash_agent_key(raw_key)


class AgentHeartbeat(models.Model):
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='heartbeats')
    ts = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, choices=Agent.Status.choices, default=Agent.Status.ONLINE)
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('-ts',)


class AgentDownload(models.Model):
    name = models.CharField(max_length=120)
    platform = models.CharField(max_length=30)
    version = models.CharField(max_length=50, default='demo')
    created_at = models.DateTimeField(auto_now_add=True)
