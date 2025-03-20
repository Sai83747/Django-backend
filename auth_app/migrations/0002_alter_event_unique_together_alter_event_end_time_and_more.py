# Generated by Django 5.1.7 on 2025-03-17 16:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='event',
            unique_together={('title', 'start_time', 'end_time', 'location')},
        ),
        migrations.AlterField(
            model_name='event',
            name='end_time',
            field=models.DateTimeField(),
        ),
        migrations.AlterField(
            model_name='event',
            name='image_url',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='event',
            name='start_time',
            field=models.DateTimeField(),
        ),
        migrations.RemoveField(
            model_name='event',
            name='date',
        ),
    ]
