"""
AJFLUX — Utilidad para enviar notificaciones push via Firebase FCM
"""
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Inicialización lazy de Firebase
_firebase_initialized = False
_firebase_unavailable = False  # evita reintentar y spam de warnings


def _init_firebase():
    global _firebase_initialized, _firebase_unavailable
    if _firebase_initialized:
        return True
    if _firebase_unavailable:
        return False
    try:
        import firebase_admin
        from firebase_admin import credentials
        from django.conf import settings

        if not firebase_admin._apps:
            cred_path = settings.FIREBASE_CREDENTIALS_PATH
            if not Path(cred_path).exists():
                logger.warning("FCM: no se encontró firebase-credentials.json en %s", cred_path)
                _firebase_unavailable = True
                return False
            cred = credentials.Certificate(str(cred_path))
            firebase_admin.initialize_app(cred)

        _firebase_initialized = True
        return True
    except ImportError:
        logger.warning("FCM: firebase-admin no instalado. Ejecuta: pip install firebase-admin")
        _firebase_unavailable = True
        return False
    except Exception as e:
        logger.error("FCM: error inicializando Firebase — %s", e)
        _firebase_unavailable = True
        return False


def send_fcm_alert(alert):
    """
    Envía notificación push a todos los usuarios con fcm_token guardado.
    """
    if not _init_firebase():
        return

    try:
        from firebase_admin import messaging
        from monitor.models import UserProfile

        tokens = list(
            UserProfile.objects.exclude(fcm_token='')
                               .values_list('fcm_token', flat=True)
        )

        if not tokens:
            logger.debug("FCM: no hay tokens registrados")
            return

        level = alert.level
        title_map = {
            'critical': '🔴 Alerta Crítica — AJFLUX',
            'warning':  '🟡 Advertencia — AJFLUX',
            'info':     '🔵 Info — AJFLUX',
        }
        title     = title_map.get(level, 'AJFLUX Monitor')
        body      = alert.message
        device_ip = alert.device.ip if alert.device else ''

        for token in tokens:
            try:
                msg = messaging.Message(
                    data={
                        'level':     level,
                        'title':     title,
                        'message':   body,
                        'device_ip': device_ip,
                    },
                    token=token,
                    android=messaging.AndroidConfig(
                        priority='high',
                        ttl=3600,
                    ),
                )
                messaging.send(msg)
                logger.info("FCM: push enviado [%s] a token ...%s", level, token[-6:])
            except messaging.UnregisteredError:
                logger.warning("FCM: token inválido, limpiando ...%s", token[-6:])
                UserProfile.objects.filter(fcm_token=token).update(fcm_token='')
            except Exception as e:
                logger.error("FCM: error enviando a token ...%s — %s", token[-6:], e)

    except Exception as e:
        logger.error("FCM: error inesperado — %s", e)