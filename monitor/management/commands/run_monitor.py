import signal
import time

from django.core.management.base import BaseCommand

from monitor.tasks import start_background_monitor, stop_background_monitor


class Command(BaseCommand):
    help = (
        "Arranca el monitoreo en segundo plano (monitor_loop) y se mantiene "
        "en ejecución. Pensado para correr como su propio proceso/contenedor "
        "(ver docker-compose.yml, servicio 'monitor'), separado de gunicorn, "
        "así no se duplica con varios workers/procesos web."
    )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("[run_monitor] Iniciando monitor en segundo plano..."))
        start_background_monitor()

        stop = {'requested': False}

        def _handle_signal(signum, frame):
            stop['requested'] = True

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

        try:
            while not stop['requested']:
                time.sleep(1)
        finally:
            self.stdout.write("[run_monitor] Deteniendo...")
            stop_background_monitor()
