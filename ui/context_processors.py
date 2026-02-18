from accounts.models import Organization


def active_organization(request):
    org = None
    if request.user.is_authenticated:
        if request.user.role == 'SUPERADMIN':
            selected_id = request.session.get('active_org_id')
            if selected_id:
                org = Organization.objects.filter(id=selected_id).first()
        else:
            org = request.user.organization
    return {
        'active_org': org,
        'all_orgs': Organization.objects.all() if request.user.is_authenticated and request.user.role == 'SUPERADMIN' else [],
    }
