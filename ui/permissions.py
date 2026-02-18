from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied

from accounts.models import Organization


class RoleRequiredMixin(LoginRequiredMixin):
    allowed_roles = set()

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        if self.allowed_roles and request.user.role not in self.allowed_roles:
            raise PermissionDenied('Insufficient role permissions.')
        return super().dispatch(request, *args, **kwargs)


class OrganizationScopedMixin:
    def get_active_organization(self):
        user = self.request.user
        if user.role == 'SUPERADMIN':
            selected_id = self.request.session.get('active_org_id')
            if selected_id:
                return Organization.objects.filter(id=selected_id).first()
            return None
        return user.organization
