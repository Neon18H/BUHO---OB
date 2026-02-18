from rest_framework import serializers


class EnrollSerializer(serializers.Serializer):
    token = serializers.CharField()
    hostname = serializers.CharField()
    ip = serializers.IPAddressField()
    os = serializers.CharField()
    version = serializers.CharField()


class HeartbeatSerializer(serializers.Serializer):
    agent_id = serializers.IntegerField()
    status = serializers.CharField()
    metadata = serializers.JSONField(required=False)
