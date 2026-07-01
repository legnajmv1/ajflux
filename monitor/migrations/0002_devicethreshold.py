"""
Migración original que creaba DeviceThreshold.
Reemplazada por 0004 — mantenida para preservar la cadena de dependencias.
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('monitor', '0001_initial'),
    ]

    operations = [
        # DeviceThreshold ya no existe — los campos se crean en 0004
    ]
