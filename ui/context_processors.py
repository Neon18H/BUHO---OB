from accounts.models import Organization


def active_organization(request):
    org = None
    if request.user.is_authenticated:
        org = request.user.organization
    return {
        'active_org': org,
        'all_orgs': Organization.objects.filter(id=request.user.organization_id) if request.user.is_authenticated and request.user.organization_id else [],
    }
