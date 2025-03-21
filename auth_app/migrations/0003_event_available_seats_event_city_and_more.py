# Generated by Django 5.1.7 on 2025-03-18 07:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0002_alter_event_unique_together_alter_event_end_time_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='event',
            name='available_seats',
            field=models.PositiveIntegerField(default=1),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='event',
            name='city',
            field=models.CharField(default=1, max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='event',
            name='price_per_seat',
            field=models.DecimalField(decimal_places=2, default=500, max_digits=10),
            preserve_default=False,
        ),
    ]
