"""
Migración 0005 — Renombrar tablas a nombres legibles:
  monitor_device        → dispositivos
  monitor_metricsnapshot → metricas
  monitor_scanreport    → reportes_escaneo
  monitor_alert         → alertas
  monitor_userprofile   → perfiles_usuario
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('monitor', '0004_device_threshold_fields'),
    ]

    operations = [
        migrations.AlterModelTable(name='device',          table='dispositivos'),
        migrations.AlterModelTable(name='metricsnapshot',  table='metricas'),
        migrations.AlterModelTable(name='scanreport',      table='reportes_escaneo'),
        migrations.AlterModelTable(name='alert',           table='alertas'),
        migrations.AlterModelTable(name='userprofile',     table='perfiles_usuario'),
    ]
