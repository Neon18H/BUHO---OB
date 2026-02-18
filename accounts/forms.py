from django import forms
from django.contrib.auth.forms import UserCreationForm

from .models import Organization, User


class UserCreateForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'organization', 'role', 'is_active')


class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'organization', 'role', 'is_active')


class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ('name', 'plan')
