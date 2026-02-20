import logging
import uuid

from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class OnboardingRequiredMiddleware(MiddlewareMixin):
    """Redirect authenticated users without organization to onboarding."""

    def process_request(self, request):
        user = getattr(request, 'user', None)
        if not user or not user.is_authenticated:
            return None
        if user.is_superuser or user.organization_id:
            return None

        allowed_prefixes = (
            '/auth/register/',
            '/auth/login/',
            '/auth/logout/',
            '/admin/',
            '/api/',
            '/static/',
        )
        if request.path.startswith(allowed_prefixes):
            return None
        return redirect(reverse('auth_register'))


class ExceptionLoggingMiddleware(MiddlewareMixin):
    """Generate traceable error IDs for unexpected exceptions."""

    def process_exception(self, request, exception):
        error_id = uuid.uuid4().hex[:12]
        request.error_id = error_id
        logger.exception('Unhandled application error id=%s path=%s', error_id, request.path)
        return None
