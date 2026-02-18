from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm

from .models import Organization

User = get_user_model()


class InitialRegistrationForm(UserCreationForm):
    organization_name = forms.CharField(max_length=120, label='Organización')
    email = forms.EmailField(required=True)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('organization_name', 'username', 'email', 'password1', 'password2')


class OrganizationUserCreateForm(UserCreationForm):
    email = forms.EmailField(required=True)
    role = forms.ChoiceField(choices=User.Role.choices)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'role', 'password1', 'password2')


class OrganizationUserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('email', 'role', 'is_active')


class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ('name', 'plan')
