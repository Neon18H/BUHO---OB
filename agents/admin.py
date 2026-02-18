from django.contrib import admin

from .models import Agent, AgentDownload, AgentEnrollmentToken, AgentHeartbeat


@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'hostname', 'ip_address', 'status', 'last_seen', 'version')
    list_filter = ('organization', 'status', 'os')
    search_fields = ('name', 'hostname', 'ip_address')


@admin.register(AgentEnrollmentToken)
class AgentEnrollmentTokenAdmin(admin.ModelAdmin):
    list_display = ('masked_token', 'organization', 'expires_at', 'is_used', 'is_revoked', 'allow_multi_use', 'created_by', 'created_at')
    list_filter = ('organization', 'is_used', 'is_revoked', 'allow_multi_use')
    search_fields = ('token',)


@admin.register(AgentHeartbeat)
class AgentHeartbeatAdmin(admin.ModelAdmin):
    list_display = ('agent', 'ts', 'status')
    list_filter = ('status',)


@admin.register(AgentDownload)
class AgentDownloadAdmin(admin.ModelAdmin):
    list_display = ('name', 'platform', 'version', 'created_at')
