# Generated by Django 5.2 on 2025-06-27 22:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0017_call_mutual_connected_seconds'),
    ]

    operations = [
        migrations.AddField(
            model_name='kyc',
            name='mobile_number',
            field=models.CharField(default=0, max_length=15),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='kyc',
            name='pan_number',
            field=models.CharField(default='ABCDE1234F', max_length=10),
            preserve_default=False,
        ),
    ]
