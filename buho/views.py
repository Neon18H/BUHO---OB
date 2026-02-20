import logging

from django.shortcuts import render

logger = logging.getLogger(__name__)


def handler500(request):
    error_id = getattr(request, 'error_id', 'unknown')
    logger.error('Rendering 500 page for error_id=%s path=%s', error_id, request.path)
    response = render(request, 'ui/error_500.html', {'error_id': error_id}, status=500)
    return response
