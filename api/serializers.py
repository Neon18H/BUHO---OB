from rest_framework import serializers

from agents.models import Agent


class EnrollSerializer(serializers.Serializer):
    token = serializers.CharField()
    hostname = serializers.CharField(max_length=120)
    ip_address = serializers.IPAddressField()
    os = serializers.CharField(max_length=120)
    arch = serializers.CharField(max_length=32, required=False, default='x86_64')
    version = serializers.CharField(max_length=50)
    name = serializers.CharField(max_length=120, required=False, allow_blank=True)


class HeartbeatSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Agent.Status.choices, required=False, default=Agent.Status.ONLINE)
    metadata = serializers.JSONField(required=False)


class MetricsSerializer(serializers.Serializer):
    ts = serializers.DateTimeField(required=False)
    metrics = serializers.ListField(child=serializers.DictField(), allow_empty=False)


class ProcessesSerializer(serializers.Serializer):
    ts = serializers.DateTimeField(required=False)
    processes = serializers.ListField(child=serializers.DictField(), allow_empty=False)


class LogsSerializer(serializers.Serializer):
    logs = serializers.ListField(child=serializers.DictField(), allow_empty=False)


class AppsSerializer(serializers.Serializer):
    ts = serializers.DateTimeField(required=False)
    apps = serializers.ListField(child=serializers.DictField(), allow_empty=False)


class DiscoverySerializer(serializers.Serializer):
    ts = serializers.DateTimeField(required=False)
    provider = serializers.ChoiceField(choices=Agent.Provider.choices, required=False)
    environment = serializers.ChoiceField(choices=Agent.Environment.choices, required=False)
    tags = serializers.ListField(child=serializers.CharField(), required=False)
    region = serializers.CharField(required=False, allow_blank=True, max_length=64)
    cloud_metadata = serializers.JSONField(required=False)
    hints = serializers.JSONField(required=False)
    apps = serializers.ListField(child=serializers.DictField(), required=False)
