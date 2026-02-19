import secrets
import uuid

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
    class Provider(models.TextChoices):
        AWS = 'AWS', 'AWS'
        AZURE = 'AZURE', 'Azure'
        GCP = 'GCP', 'GCP'
        RAILWAY = 'RAILWAY', 'Railway'
        ON_PREM = 'ON_PREM', 'On-Prem'
        OTHER = 'OTHER', 'Other'

    class Environment(models.TextChoices):
        DEV = 'DEV', 'Dev'
        STAGE = 'STAGE', 'Stage'
        PROD = 'PROD', 'Prod'

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
    provider = models.CharField(max_length=20, choices=Provider.choices, default=Provider.OTHER)
    environment = models.CharField(max_length=20, choices=Environment.choices, default=Environment.PROD)
    tags_json = models.JSONField(default=list, blank=True)
    region = models.CharField(max_length=64, blank=True)
    cloud_metadata_json = models.JSONField(default=dict, blank=True)
    health_score = models.PositiveSmallIntegerField(default=100)
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
        AGENT_OFFLINE = 'AGENT_OFFLINE', 'Agent heartbeat missing'
        HTTP_5XX_SPIKE = 'HTTP_5XX_SPIKE', 'HTTP 5xx spike'

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


class DetectedApp(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='detected_apps')
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='detected_apps')
    kind = models.CharField(max_length=64)
    name = models.CharField(max_length=120)
    runtime = models.CharField(max_length=64, blank=True)
    framework = models.CharField(max_length=64, blank=True)
    server = models.CharField(max_length=64, blank=True)
    pid = models.IntegerField(null=True, blank=True)
    ports_json = models.JSONField(default=list, blank=True)
    process_hints_json = models.JSONField(default=dict, blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)
    app_health_score = models.PositiveSmallIntegerField(default=100)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ('name',)
        indexes = [models.Index(fields=['organization', 'agent', 'kind', 'last_seen'])]


class AppServiceMap(models.Model):
    app = models.ForeignKey(DetectedApp, on_delete=models.CASCADE, related_name='service_maps')
    service_name = models.CharField(max_length=64)
    service_kind = models.CharField(max_length=64)
    port = models.PositiveIntegerField(null=True, blank=True)
    metadata_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('service_name',)


class AgentCommand(models.Model):
    class CommandType(models.TextChoices):
        START_NOCTURNAL_SCAN = 'START_NOCTURNAL_SCAN', 'Start nocturnal scan'
        STOP_NOCTURNAL_SCAN = 'STOP_NOCTURNAL_SCAN', 'Stop nocturnal scan'
        SET_NOCTURNAL_CONFIG = 'SET_NOCTURNAL_CONFIG', 'Set nocturnal config'

    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        SENT = 'SENT', 'Sent'
        ACKED = 'ACKED', 'Acked'
        RUNNING = 'RUNNING', 'Running'
        COMPLETED = 'COMPLETED', 'Completed'
        FAILED = 'FAILED', 'Failed'
        CANCELED = 'CANCELED', 'Canceled'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='agent_commands')
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='commands')
    command_type = models.CharField(max_length=64, choices=CommandType.choices)
    payload_json = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    issued_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('-created_at',)
        indexes = [models.Index(fields=['organization', 'agent', 'status', 'created_at'])]


class NocturnalScanRun(models.Model):
    class Status(models.TextChoices):
        RUNNING = 'RUNNING', 'Running'
        COMPLETED = 'COMPLETED', 'Completed'
        FAILED = 'FAILED', 'Failed'
        STOPPED = 'STOPPED', 'Stopped'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='nocturnal_runs')
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='nocturnal_runs')
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.RUNNING)
    started_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)
    stats_json = models.JSONField(default=dict, blank=True)
    last_progress = models.PositiveSmallIntegerField(default=0)
    last_message = models.CharField(max_length=255, blank=True)
    config_snapshot_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('-started_at',)
        indexes = [models.Index(fields=['organization', 'agent', 'status', 'started_at'])]


class SecurityFinding(models.Model):
    class Severity(models.TextChoices):
        LOW = 'LOW', 'Low'
        MED = 'MED', 'Medium'
        HIGH = 'HIGH', 'High'
        CRITICAL = 'CRITICAL', 'Critical'

    class Category(models.TextChoices):
        YARA_MATCH = 'YARA_MATCH', 'YARA match'
        VT_HASH_MATCH = 'VT_HASH_MATCH', 'VirusTotal hash match'
        SUSPICIOUS_FILE = 'SUSPICIOUS_FILE', 'Suspicious file'

    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Open'
        ACK = 'ACK', 'Ack'
        RESOLVED = 'RESOLVED', 'Resolved'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='security_findings')
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='security_findings')
    fingerprint = models.CharField(max_length=64)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MED)
    category = models.CharField(max_length=32, choices=Category.choices)
    title = models.CharField(max_length=255)
    details_json = models.JSONField(default=dict, blank=True)
    evidence_json = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)

    class Meta:
        ordering = ('-last_seen',)
        unique_together = ('organization', 'agent', 'fingerprint')
        indexes = [models.Index(fields=['organization', 'agent', 'severity', 'status', 'last_seen'])]


class HashReputationCache(models.Model):
    sha256 = models.CharField(max_length=64, unique=True)
    vt_json = models.JSONField(default=dict, blank=True)
    last_checked = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()

    class Meta:
        ordering = ('-last_checked',)
