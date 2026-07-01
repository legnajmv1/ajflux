"""
Migración 0004 — Normalización DB:
  1. Agrega los campos de umbral directamente en monitor_device
  2. Copia datos de monitor_devicethreshold si la tabla existe
  3. Elimina la tabla monitor_devicethreshold si existe
"""
from django.db import migrations, models


def copiar_umbrales(apps, schema_editor):
    """Copia datos de DeviceThreshold → Device solo si la tabla existía."""
    db = schema_editor.connection
    tablas = db.introspection.table_names()
    if 'monitor_devicethreshold' not in tablas:
        return  # Base de datos nueva, nada que copiar
    with db.cursor() as cursor:
        cursor.execute("""
            UPDATE monitor_device SET
                latency_warning  = (SELECT latency_warning  FROM monitor_devicethreshold WHERE device_id = monitor_device.id),
                latency_critical = (SELECT latency_critical FROM monitor_devicethreshold WHERE device_id = monitor_device.id),
                jitter_warning   = (SELECT jitter_warning   FROM monitor_devicethreshold WHERE device_id = monitor_device.id),
                loss_warning     = (SELECT loss_warning     FROM monitor_devicethreshold WHERE device_id = monitor_device.id),
                qos_minimum      = (SELECT qos_minimum      FROM monitor_devicethreshold WHERE device_id = monitor_device.id),
                threshold_notes  = COALESCE(
                    (SELECT notes FROM monitor_devicethreshold WHERE device_id = monitor_device.id), '')
            WHERE EXISTS (
                SELECT 1 FROM monitor_devicethreshold WHERE device_id = monitor_device.id
            );
        """)


def eliminar_tabla_vieja(apps, schema_editor):
    """Elimina monitor_devicethreshold solo si existe."""
    db = schema_editor.connection
    tablas = db.introspection.table_names()
    if 'monitor_devicethreshold' in tablas:
        with db.cursor() as cursor:
            cursor.execute("DROP TABLE monitor_devicethreshold;")


class Migration(migrations.Migration):

    dependencies = [
        ('monitor', '0003_userprofile'),
    ]

    operations = [
        migrations.AddField(model_name='device', name='latency_warning',
            field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name='device', name='latency_critical',
            field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name='device', name='jitter_warning',
            field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name='device', name='loss_warning',
            field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name='device', name='qos_minimum',
            field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name='device', name='threshold_notes',
            field=models.TextField(blank=True, default='')),
        migrations.RunPython(copiar_umbrales,   migrations.RunPython.noop),
        migrations.RunPython(eliminar_tabla_vieja, migrations.RunPython.noop),
    ]
