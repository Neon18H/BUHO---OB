from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from accounts.models import Organization
from agents.models import AgentEnrollmentToken

User = get_user_model()


class AgentTokenPermissionTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name='Org 1')
        self.create_url = reverse('agents:token_create')
        self.install_url = reverse('agents:install')

    def _build_payload(self):
        return {
            'expiration': '24h',
            'server_name_optional': 'srv-01',
            'tags': 'prod,web',
            'allow_multi_use': 'on',
        }

    def test_org_admin_can_create_token(self):
        user = User.objects.create_user(
            username='org-admin',
            password='pass1234',
            role='ORG_ADMIN',
            organization=self.organization,
        )
        self.client.force_login(user)

        response = self.client.post(self.create_url, data=self._build_payload(), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(AgentEnrollmentToken.objects.filter(created_by=user).exists())

    def test_analyst_cannot_create_token_returns_redirect_with_message(self):
        user = User.objects.create_user(
            username='analyst-user',
            password='pass1234',
            role='ANALYST',
            organization=self.organization,
        )
        self.client.force_login(user)

        response = self.client.post(self.create_url, data=self._build_payload(), follow=True)

        self.assertRedirects(response, self.install_url)
        self.assertFalse(AgentEnrollmentToken.objects.exists())
        messages = [message.message for message in response.context['messages']]
        self.assertIn('No tienes permisos para realizar esta acción.', messages)

    def test_superuser_bypass(self):
        user = User.objects.create_superuser(
            username='django-super',
            email='super@example.com',
            password='pass1234',
            role='VIEWER',
            organization=None,
        )
        self.client.force_login(user)

        response = self.client.post(self.create_url, data=self._build_payload(), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(AgentEnrollmentToken.objects.filter(created_by=user).exists())

    def test_non_superadmin_without_organization_redirects_with_message(self):
        user = User.objects.create_user(
            username='orphan-admin',
            password='pass1234',
            role='ORG_ADMIN',
            organization=None,
        )
        self.client.force_login(user)

        response = self.client.get(self.install_url, follow=True)

        self.assertRedirects(response, reverse('ui:settings'))
        messages = [message.message for message in response.context['messages']]
        self.assertIn(
            'Tu usuario no tiene organización asignada. Contacta a un administrador o configura tu perfil.',
            messages,
        )
