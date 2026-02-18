from django.contrib import admin

from .models import Agent, AgentEnrollmentToken


@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'hostname', 'ip_address', 'status', 'last_seen', 'version')
    list_filter = ('organization', 'status', 'os')
    search_fields = ('name', 'hostname', 'ip_address')


@admin.register(AgentEnrollmentToken)
class AgentEnrollmentTokenAdmin(admin.ModelAdmin):
    list_display = ('masked_token', 'organization', 'expires_at', 'is_used', 'is_revoked', 'created_by', 'created_at')
    list_filter = ('organization', 'is_used', 'is_revoked')
    search_fields = ('token',)
