# Generated manually for local MVP
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='agent',
            name='agent_key_hash',
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name='agent',
            name='arch',
            field=models.CharField(default='x86_64', max_length=32),
        ),
        migrations.AddField(
            model_name='agentenrollmenttoken',
            name='allow_multi_use',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='agentenrollmenttoken',
            name='server_name_optional',
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AddField(
            model_name='agentenrollmenttoken',
            name='tags_json',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.CreateModel(
            name='AgentDownload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120)),
                ('platform', models.CharField(max_length=30)),
                ('version', models.CharField(default='demo', max_length=50)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='AgentHeartbeat',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ts', models.DateTimeField(default=django.utils.timezone.now)),
                ('status', models.CharField(choices=[('ONLINE', 'Online'), ('OFFLINE', 'Offline'), ('DEGRADED', 'Degraded')], default='ONLINE', max_length=20)),
                ('metadata_json', models.JSONField(blank=True, default=dict)),
                ('agent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='heartbeats', to='agents.agent')),
            ],
            options={'ordering': ('-ts',)},
        ),
    ]
