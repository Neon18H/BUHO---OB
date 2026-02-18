from django.contrib.auth.models import AbstractUser
from django.db import models


class Organization(models.Model):
    class Plan(models.TextChoices):
        FREE = 'FREE', 'Free'
        PRO = 'PRO', 'Pro'
        ENTERPRISE = 'ENTERPRISE', 'Enterprise'

    name = models.CharField(max_length=120, unique=True)
    plan = models.CharField(max_length=20, choices=Plan.choices, default=Plan.FREE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class User(AbstractUser):
    class Role(models.TextChoices):
        SUPERADMIN = 'SUPERADMIN', 'Super Admin'
        ORG_ADMIN = 'ORG_ADMIN', 'Org Admin'
        ANALYST = 'ANALYST', 'Analyst'
        VIEWER = 'VIEWER', 'Viewer'

    organization = models.ForeignKey(
        Organization,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='users',
    )
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.VIEWER)

    def can_manage_settings(self):
        return self.role in {self.Role.SUPERADMIN, self.Role.ORG_ADMIN}

    def in_same_org(self, other):
        return self.organization_id and self.organization_id == other.organization_id
