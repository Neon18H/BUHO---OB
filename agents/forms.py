from datetime import timedelta

from django import forms
from django.utils import timezone


class TokenCreateForm(forms.Form):
    expiration = forms.ChoiceField(
        choices=(
            ('1h', '1 hour'),
            ('24h', '24 hours'),
            ('7d', '7 days'),
        ),
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    def get_expires_at(self):
        exp = self.cleaned_data['expiration']
        mapping = {
            '1h': timedelta(hours=1),
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
        }
        return timezone.now() + mapping[exp]
