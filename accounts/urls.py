from django.urls import path

from ui.views import BuhoLoginView, BuhoLogoutView, OrganizationSwitchView, RegisterView

app_name = 'accounts'

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', BuhoLoginView.as_view(), name='login'),
    path('auth/logout/', BuhoLogoutView.as_view(), name='logout'),
    path('switch-organization/', OrganizationSwitchView.as_view(), name='switch_organization'),
]
