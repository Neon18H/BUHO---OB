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
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return f'Token {self.masked_token}'

    @property
    def masked_token(self):
        return f'{self.token[:8]}...{self.token[-6:]}' if len(self.token) > 16 else self.token

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
    version = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OFFLINE)
    last_seen = models.DateTimeField(null=True, blank=True)
    enrolled_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ('name',)

    def __str__(self):
        return self.name
