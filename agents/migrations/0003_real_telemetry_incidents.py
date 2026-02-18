import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0002_agent_expansion'),
    ]

    operations = [
        migrations.AlterField(
            model_name='agent',
            name='agent_key_hash',
            field=models.CharField(blank=True, max_length=256),
        ),
        migrations.AlterUniqueTogether(
            name='agent',
            unique_together={('organization', 'hostname')},
        ),
        migrations.CreateModel(
            name='Incident',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('CPU_SPIKE', 'CPU > 90% (3 samples)'), ('DISK_CRITICAL', 'Disk root > 90%'), ('LOG_ERROR_FLOOD', 'Error logs flood')], max_length=32)),
                ('severity', models.CharField(choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('CRITICAL', 'Critical')], max_length=16)),
                ('status', models.CharField(choices=[('OPEN', 'Open'), ('ACKED', 'Acked'), ('RESOLVED', 'Resolved')], default='OPEN', max_length=16)),
                ('started_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('last_seen', models.DateTimeField(default=django.utils.timezone.now)),
                ('context_json', models.JSONField(blank=True, default=dict)),
                ('agent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='incidents', to='agents.agent')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='incidents', to='accounts.organization')),
            ],
            options={'ordering': ('-last_seen',)},
        ),
        migrations.CreateModel(
            name='LogEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('level', models.CharField(choices=[('INFO', 'Info'), ('WARN', 'Warn'), ('ERROR', 'Error')], default='INFO', max_length=16)),
                ('source', models.CharField(default='agent', max_length=120)),
                ('message', models.TextField()),
                ('ts', models.DateTimeField(default=django.utils.timezone.now)),
                ('fields_json', models.JSONField(blank=True, default=dict)),
                ('agent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='log_entries', to='agents.agent')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='log_entries', to='accounts.organization')),
            ],
            options={'ordering': ('-ts',)},
        ),
        migrations.CreateModel(
            name='MetricPoint',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120)),
                ('value', models.FloatField()),
                ('unit', models.CharField(blank=True, max_length=32)),
                ('ts', models.DateTimeField(default=django.utils.timezone.now)),
                ('labels_json', models.JSONField(blank=True, default=dict)),
                ('agent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='metric_points', to='agents.agent')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='metric_points', to='accounts.organization')),
            ],
            options={'ordering': ('-ts',)},
        ),
        migrations.CreateModel(
            name='ProcessSample',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pid', models.IntegerField()),
                ('name', models.CharField(max_length=255)),
                ('cpu', models.FloatField(default=0.0)),
                ('mem', models.FloatField(default=0.0)),
                ('user', models.CharField(blank=True, max_length=255)),
                ('cmdline_redacted', models.TextField(blank=True)),
                ('ts', models.DateTimeField(default=django.utils.timezone.now)),
                ('agent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='process_samples', to='agents.agent')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='process_samples', to='accounts.organization')),
            ],
            options={'ordering': ('-ts',)},
        ),
        migrations.AddIndex(model_name='logentry', index=models.Index(fields=['organization', 'agent', 'level', 'ts'], name='agents_logen_organiz_a4d664_idx')),
        migrations.AddIndex(model_name='metricpoint', index=models.Index(fields=['organization', 'agent', 'name', 'ts'], name='agents_metri_organiz_5f6fc1_idx')),
        migrations.AddIndex(model_name='processsample', index=models.Index(fields=['organization', 'agent', 'ts'], name='agents_proce_organiz_a4784a_idx')),
    ]
