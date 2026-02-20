from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ('accounts', '0001_initial'),
        ('agents', '0007_alter_hashreputationcache_options_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='SecurityEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ts', models.DateTimeField(db_index=True)),
                ('source', models.CharField(max_length=64)),
                ('event_type', models.CharField(max_length=64)),
                ('severity', models.CharField(choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('CRITICAL', 'Critical')], default='LOW', max_length=16)),
                ('title', models.CharField(max_length=180)),
                ('message', models.TextField(blank=True)),
                ('raw_json', models.JSONField(blank=True, default=dict)),
                ('tags', models.JSONField(blank=True, default=list)),
                ('status', models.CharField(default='OPEN', max_length=16)),
                ('agent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='security_events', to='agents.agent')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='security_events', to='accounts.organization')),
            ],
        ),
        migrations.CreateModel(
            name='DetectionRule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120)),
                ('enabled', models.BooleanField(default=True)),
                ('query_json', models.JSONField(blank=True, default=dict)),
                ('threshold', models.PositiveIntegerField(default=1)),
                ('window_seconds', models.PositiveIntegerField(default=300)),
                ('severity', models.CharField(default='MEDIUM', max_length=16)),
                ('action', models.CharField(default='create_alert', max_length=32)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='detection_rules', to='accounts.organization')),
            ],
        ),
        migrations.CreateModel(
            name='CorrelatedAlert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('severity', models.CharField(max_length=16)),
                ('title', models.CharField(max_length=180)),
                ('description', models.TextField(blank=True)),
                ('status', models.CharField(choices=[('OPEN', 'Open'), ('ACK', 'Ack'), ('RESOLVED', 'Resolved')], default='OPEN', max_length=16)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='correlated_alerts', to='accounts.organization')),
                ('linked_events', models.ManyToManyField(blank=True, related_name='alerts', to='soc.securityevent')),
            ],
        ),
    ]
