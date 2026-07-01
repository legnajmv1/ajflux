from django.apps import AppConfig


class MonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'monitor'

    def ready(self):
        import os
        if os.environ.get('RUN_MAIN') == 'true':
            try:
                from monitor.tasks import start_background_monitor
                start_background_monitor()
            except Exception as e:
                print(f"[AJFLUX] Monitor background no pudo iniciar: {e}")




#------ sudo venv/bin/python manage.py runserver 0.0.0.0:8000
#------ cloudflared tunnel --url http://localhost:8000
