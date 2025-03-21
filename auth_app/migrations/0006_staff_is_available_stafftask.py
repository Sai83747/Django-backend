# Generated by Django 5.1.7 on 2025-03-18 22:12

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0005_booking_booking_amount'),
    ]

    operations = [
        migrations.AddField(
            model_name='staff',
            name='is_available',
            field=models.BooleanField(default=True),
        ),
        migrations.CreateModel(
            name='StaffTask',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('due_date', models.DateTimeField(blank=True, null=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('in_progress', 'In Progress'), ('completed', 'Completed')], default='pending', max_length=20)),
                ('progress_percentage', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('assigned_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='tasks_assigned', to='auth_app.eventmanager')),
                ('event', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='tasks', to='auth_app.event')),
                ('staff', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tasks', to='auth_app.staff')),
            ],
            options={
                'unique_together': {('staff', 'event', 'title')},
            },
        ),
    ]
