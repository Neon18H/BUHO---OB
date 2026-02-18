from django.urls import path

from ui.views import BuhoLoginView, BuhoLogoutView, OrganizationSwitchView

app_name = 'accounts'

urlpatterns = [
    path('login/', BuhoLoginView.as_view(), name='login'),
    path('logout/', BuhoLogoutView.as_view(), name='logout'),
    path('switch-organization/', OrganizationSwitchView.as_view(), name='switch_organization'),
]
