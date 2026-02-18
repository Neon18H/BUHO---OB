from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.urls import reverse

from accounts.models import Organization


class BaseRoleRequiredMixin(LoginRequiredMixin):
    allowed_roles = set()

    def get_allowed_roles(self):
        return set(self.allowed_roles or set())

    def has_role_permission(self, request):
        user = request.user
        if not user.is_authenticated:
            return False
        if user.is_superuser:
            return True
        allowed_roles = self.get_allowed_roles()
        return not allowed_roles or user.role in allowed_roles


class RoleRequiredAPIMixin(BaseRoleRequiredMixin):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        if not self.has_role_permission(request):
            raise PermissionDenied('Insufficient role permissions.')
        return super().dispatch(request, *args, **kwargs)


class RoleRequiredUIMixin(BaseRoleRequiredMixin):
    permission_denied_message = 'No tienes permisos para realizar esta acción.'
    permission_redirect_url = 'ui:overview'
    require_organization = False
    missing_organization_message = (
        'Tu usuario no tiene organización asignada. Contacta a un administrador o configura tu perfil.'
    )
    missing_organization_redirect_url = 'ui:settings'

    def get_permission_redirect_url(self):
        return self.permission_redirect_url or 'ui:overview'

    def get_missing_organization_redirect_url(self):
        return self.missing_organization_redirect_url or 'ui:settings'

    def _resolve_redirect(self, request, redirect_to):
        if not redirect_to:
            return redirect('ui:overview')
        if '/' in str(redirect_to):
            return redirect(redirect_to)
        try:
            return redirect(reverse(redirect_to))
        except Exception:
            return redirect(redirect_to)

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()

        if not self.has_role_permission(request):
            messages.error(request, self.permission_denied_message)
            return self._resolve_redirect(request, self.get_permission_redirect_url())

        needs_org = self.require_organization and not request.user.is_superuser
        if needs_org and not request.user.organization_id:
            messages.error(request, self.missing_organization_message)
            return self._resolve_redirect(request, self.get_missing_organization_redirect_url())

        return super().dispatch(request, *args, **kwargs)


class RoleRequiredMixin(RoleRequiredUIMixin):
    """Backward compatible alias for existing UI views."""


class OrganizationScopedMixin:
    def get_active_organization(self):
        return self.request.user.organization
