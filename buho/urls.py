from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(('ui.urls', 'ui'), namespace='ui')),
    path('', include(('accounts.urls', 'accounts'), namespace='accounts')),
    path('agents/', include(('agents.urls', 'agents'), namespace='agents')),
]
