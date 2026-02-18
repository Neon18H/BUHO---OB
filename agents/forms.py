from datetime import timedelta

from django import forms
from django.utils import timezone


class TokenCreateForm(forms.Form):
    server_name_optional = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'srv-prod-01'}))
    tags = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'prod,web,critical'}))
    expiration = forms.ChoiceField(
        choices=(
            ('1h', '1 hour'),
            ('24h', '24 hours'),
            ('7d', '7 days'),
        ),
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    allow_multi_use = forms.BooleanField(required=False, widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}))

    def get_expires_at(self):
        exp = self.cleaned_data['expiration']
        mapping = {
            '1h': timedelta(hours=1),
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
        }
        return timezone.now() + mapping[exp]

    def get_tags(self):
        raw = self.cleaned_data.get('tags', '').strip()
        return [tag.strip() for tag in raw.split(',') if tag.strip()]
