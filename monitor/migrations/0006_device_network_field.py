"""
Migración 0006 — Agrega campo 'network' al modelo Device
para registrar a qué red pertenece cada dispositivo.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monitor', '0005_renombrar_tablas'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='network',
            field=models.CharField(blank=True, default='', max_length=50),
        ),
    ]
