# Generated by Django 5.1.7 on 2025-03-21 04:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0007_alter_staff_event_manager'),
    ]

    operations = [
        migrations.AddField(
            model_name='stafftask',
            name='feedback',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='stafftask',
            name='rating',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
