from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import Organization, User


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'plan', 'created_at')


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    fieldsets = DjangoUserAdmin.fieldsets + ((
        'Buho Access', {'fields': ('organization', 'role')}
    ),)
    list_display = ('username', 'email', 'role', 'organization', 'is_active', 'is_staff')
