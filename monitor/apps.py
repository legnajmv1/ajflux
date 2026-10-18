from django.apps import AppConfig


class MonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'monitor'

    # El monitoreo en segundo plano YA NO arranca aquí. Con gunicorn (varios
    # workers) o varios procesos de runserver, cada uno ejecutaría su propio
    # monitor_loop y duplicaría pings/escaneos/alertas. Ahora arranca
    # únicamente desde su propio proceso: `python manage.py run_monitor`
    # (ver docker-compose.yml, servicio "monitor").
