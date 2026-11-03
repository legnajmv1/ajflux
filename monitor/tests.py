"""
AJFLUX — Pruebas de seguridad de la API.
"""
from django.test import TestCase, Client
from django.middleware.csrf import get_token
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.authtoken.models import Token

from monitor.models import UserProfile

User = get_user_model()

READ_ENDPOINTS = [
    '/api/live/',
    '/api/dispositivos/',
    '/api/dispositivos/por-red/',
    '/api/metricas/',
    '/api/topologia/',
    '/api/topologia/analizar/',
    '/api/reportes/',
    '/api/alertas/',
    '/api/scan/status/',
    '/api/network/',
    '/api/umbrales/',
    '/api/monitor/estado/',
    '/reportes/exportar-pdf/',
]


class AuthenticationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username='viewer1', password='clave-segura-123')
        UserProfile.objects.create(user=self.user, role='viewer')
        self.token = Token.objects.create(user=self.user)
        self.client = Client()

    def test_read_endpoints_require_authentication(self):
        for url in READ_ENDPOINTS:
            with self.subTest(url=url):
                resp = self.client.get(url)
                self.assertEqual(resp.status_code, 401, f'{url} debería exigir autenticación')

    def test_read_endpoints_accept_valid_token(self):
        for url in READ_ENDPOINTS:
            with self.subTest(url=url):
                resp = self.client.get(url, HTTP_AUTHORIZATION=f'Token {self.token.key}')
                self.assertEqual(resp.status_code, 200, f'{url} debería responder 200 con token válido')


class PermissionTests(TestCase):
    def setUp(self):
        cache.clear()
        self.viewer = User.objects.create_user(username='viewer2', password='clave-segura-123')
        UserProfile.objects.create(user=self.viewer, role='viewer')
        self.viewer_token = Token.objects.create(user=self.viewer)
        self.client = Client()

    def test_viewer_cannot_resolve_alert(self):
        resp = self.client.post(
            '/api/alertas/1/resolver/', HTTP_AUTHORIZATION=f'Token {self.viewer_token.key}')
        self.assertEqual(resp.status_code, 403)

    def test_viewer_cannot_save_threshold(self):
        resp = self.client.post(
            '/api/umbrales/1/guardar/', data={}, content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.viewer_token.key}')
        self.assertEqual(resp.status_code, 403)

    def test_viewer_cannot_delete_threshold(self):
        resp = self.client.delete(
            '/api/umbrales/1/eliminar/', HTTP_AUTHORIZATION=f'Token {self.viewer_token.key}')
        self.assertEqual(resp.status_code, 403)


class CsrfTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_user(username='admin1', password='clave-segura-123')
        UserProfile.objects.create(user=self.admin, role='admin')
        from monitor.models import Device
        self.device = Device.objects.create(ip='10.0.0.99')

    def test_session_post_without_csrf_token_is_rejected(self):
        c = Client(enforce_csrf_checks=True)
        c.login(username='admin1', password='clave-segura-123')
        resp = c.post(f'/api/umbrales/{self.device.id}/guardar/', data='{}', content_type='application/json')
        self.assertEqual(resp.status_code, 403)

    def test_session_post_with_csrf_token_is_accepted(self):
        c = Client(enforce_csrf_checks=True)
        c.login(username='admin1', password='clave-segura-123')
        token = get_token(c.get('/').wsgi_request)
        resp = c.post(
            f'/api/umbrales/{self.device.id}/guardar/', data='{}', content_type='application/json',
            HTTP_X_CSRFTOKEN=token)
        self.assertEqual(resp.status_code, 200)

    def test_token_auth_post_is_exempt_from_csrf(self):
        c = Client(enforce_csrf_checks=True)
        token = Token.objects.create(user=self.admin)
        resp = c.post(
            f'/api/umbrales/{self.device.id}/guardar/', data='{}', content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertEqual(resp.status_code, 200)


class LoginRateLimitTests(TestCase):
    def setUp(self):
        cache.clear()
        User.objects.create_user(username='alguien', password='clave-correcta-123')

    def test_app_login_blocks_after_five_failed_attempts(self):
        for _ in range(5):
            resp = self.client.post(
                '/api/app/login/',
                data='{"username": "alguien", "password": "mala"}',
                content_type='application/json',
            )
            self.assertEqual(resp.status_code, 401)
        resp = self.client.post(
            '/api/app/login/',
            data='{"username": "alguien", "password": "mala"}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 429)

    def test_web_login_blocks_after_five_failed_attempts(self):
        for _ in range(5):
            resp = self.client.post('/login/', data={'username': 'alguien', 'password': 'mala'})
            self.assertEqual(resp.status_code, 200)
        resp = self.client.post('/login/', data={'username': 'alguien', 'password': 'mala'})
        self.assertEqual(resp.status_code, 429)


# ══════════════════════════════════════════════════════════
# CAJA BLANCA — lógica interna (la red se simula con unittest.mock)
# ══════════════════════════════════════════════════════════
import datetime
from unittest import mock

from django.test import SimpleTestCase
from django.utils import timezone

from monitor import scanner, tasks
from monitor.models import Alert, Device, MetricSnapshot


class CalculateQosScoreTests(SimpleTestCase):
    """50 % latencia + 30 % jitter + 20 % pérdida, por tramos."""

    def assertQos(self, lat, jit, loss, esperado):
        self.assertAlmostEqual(tasks.calculate_qos_score(lat, jit, loss), esperado, places=1,
                               msg=f'lat={lat} jit={jit} loss={loss}')

    def test_sin_latencia_devuelve_cero(self):
        self.assertQos(None, 0, 0, 0.0)

    def test_tramos_de_latencia(self):
        casos = [
            (10, 100.0),    # < 50 ms        -> 100
            (49.9, 100.0),
            (50, 100.0),    # 50-150 ms      -> 100 - (lat-50)*0.5
            (100, 87.5),
            (150, 75.0),    # 150-300 ms     -> 50 - (lat-150)*0.3
            (200, 67.5),
            (300, 52.5),    # >= 300 ms      -> max(0, 5 - (lat-300)*0.01)
            (400, 52.0),
            (1000, 50.0),   # el tramo no baja de 0
        ]
        for lat, esperado in casos:
            with self.subTest(lat=lat):
                self.assertQos(lat, 0, 0, esperado)

    def test_tramos_de_jitter(self):
        casos = [
            (None, 100.0),  # None se trata como 0
            (5, 100.0),     # < 10 ms        -> 100
            (10, 100.0),    # 10-30 ms       -> 100 - (j-10)*2
            (20, 94.0),
            (30, 88.0),     # >= 30 ms       -> max(0, 60 - (j-30)*1.5)
            (40, 83.5),
            (100, 70.0),    # el tramo no baja de 0
        ]
        for jit, esperado in casos:
            with self.subTest(jitter=jit):
                self.assertQos(10, jit, 0, esperado)

    def test_tramos_de_perdida(self):
        casos = [
            (None, 100.0),  # None se trata como 0
            (0, 100.0),     # 0 %            -> 100
            (0.5, 98.0),    # < 1 %          -> 90
            (1, 94.0),      # 1-5 %          -> 80 - loss*10
            (2, 92.0),
            (5, 83.0),      # >= 5 %         -> max(0, 30 - loss*3)
            (10, 80.0),
            (100, 80.0),    # el tramo no baja de 0
        ]
        for loss, esperado in casos:
            with self.subTest(loss=loss):
                self.assertQos(10, 0, loss, esperado)

    def test_peor_caso_y_redondeo(self):
        self.assertQos(1000, 100, 100, 0.0)
        self.assertEqual(tasks.calculate_qos_score(123.456, 0, 0), 81.6)   # 63.272*0.5 + 30 + 20 = 81.636


class GetVendorFromMacTests(SimpleTestCase):
    def test_mac_vacia_o_invalida(self):
        for mac in ('', None, 'Unknown', 'AB:CD'):
            with self.subTest(mac=mac):
                self.assertEqual(scanner.get_vendor_from_mac(mac), 'Desconocido')

    @mock.patch('monitor.scanner._load_nmap_oui_prefixes', return_value={'AABBCC': 'Fabricante X'})
    def test_usa_base_de_nmap_y_normaliza_formato(self, _):
        for mac in ('aa:bb:cc:11:22:33', 'AA-BB-CC-11-22-33', 'aabbcc112233'):
            with self.subTest(mac=mac):
                self.assertEqual(scanner.get_vendor_from_mac(mac), 'Fabricante X')

    @mock.patch('monitor.scanner._load_nmap_oui_prefixes', return_value={})
    def test_respaldo_con_diccionario_interno(self, _):
        self.assertEqual(scanner.get_vendor_from_mac('B8:27:EB:00:00:01'), 'Raspberry Pi')
        self.assertEqual(scanner.get_vendor_from_mac('00:0C:29:00:00:01'), 'VMware')
        self.assertEqual(scanner.get_vendor_from_mac('12:34:56:00:00:01'), 'Desconocido')

    def test_carga_del_archivo_de_prefijos(self):
        contenido = '# comentario\n\n000C29 VMware, Inc.\nXYZ incorrecto\nB827EB Raspberry Pi Foundation\n'
        with mock.patch.object(scanner, '_nmap_oui_cache', None), \
             mock.patch('builtins.open', mock.mock_open(read_data=contenido)):
            prefijos = scanner._load_nmap_oui_prefixes()
            self.assertEqual(prefijos, {'000C29': 'VMware, Inc.', 'B827EB': 'Raspberry Pi Foundation'})
            self.assertEqual(scanner.get_vendor_from_mac('b8:27:eb:12:34:56'), 'Raspberry Pi Foundation')

    def test_archivo_de_prefijos_inexistente(self):
        with mock.patch.object(scanner, '_nmap_oui_cache', None), \
             mock.patch('builtins.open', side_effect=FileNotFoundError):
            self.assertEqual(scanner._load_nmap_oui_prefixes(), {})


@mock.patch('monitor.scanner._load_nmap_oui_prefixes', return_value={})
class DetectDeviceTypeTests(SimpleTestCase):
    def test_por_sistema_operativo(self, _):
        casos = [
            ('Cisco IOS 15.2', [], 'router'),
            ('Android 11', [], 'phone'),
            ('Microsoft Windows Server 2019', [], 'server'),
            ('Linux 5.4', [22], 'server'),
            ('Microsoft Windows 10', [], 'desktop'),
            ('Apple macOS 13', [], 'laptop'),
        ]
        for os_info, puertos, esperado in casos:
            with self.subTest(os=os_info):
                self.assertEqual(scanner.detect_device_type('', '', puertos, os_info), esperado)

    def test_por_nombre_de_equipo(self, _):
        casos = [
            ('router-oficina', 'router'),
            ('sw-piso2', 'switch'),
            ('unifi-ap', 'wifi'),
            ('nas-respaldo', 'server'),
            ('ipcam-entrada', 'camera'),
            ('galaxy-s21', 'phone'),
            ('firetv-sala', 'tv'),
            ('epson-l3150', 'printer'),
        ]
        for host, esperado in casos:
            with self.subTest(hostname=host):
                self.assertEqual(scanner.detect_device_type(host, '', []), esperado)

    def test_por_fabricante(self, _):
        casos = [
            ('B8:27:EB:00:00:01', 'iot'),      # Raspberry Pi
            ('00:1C:F0:00:00:01', 'router'),   # Cisco
            ('28:CD:C1:00:00:01', 'laptop'),   # Apple
            ('F4:31:C3:00:00:01', 'phone'),    # Samsung
            ('B4:7C:9C:00:00:01', 'desktop'),  # Dell
        ]
        for mac, esperado in casos:
            with self.subTest(mac=mac):
                self.assertEqual(scanner.detect_device_type('', mac, []), esperado)

    def test_por_puertos_y_valor_por_defecto(self, _):
        self.assertEqual(scanner.detect_device_type('', '', [3389]), 'desktop')
        self.assertEqual(scanner.detect_device_type('', '', [443]), 'server')
        self.assertEqual(scanner.detect_device_type('', '', [], 'Linux 5.4'), 'desktop')
        self.assertEqual(scanner.detect_device_type('', '', []), 'desktop')

    def test_el_sistema_operativo_tiene_prioridad(self, _):
        # Nombre de cámara y MAC de Apple, pero nmap dice Android
        self.assertEqual(scanner.detect_device_type('cam-1', '28:CD:C1:00:00:01', [], 'Android 10'), 'phone')


class PingHostTests(SimpleTestCase):
    """ping_host con subprocess.run simulado (sin tráfico real)."""

    def _run(self, salida):
        return mock.patch('monitor.scanner.subprocess.run',
                          return_value=mock.Mock(stdout=salida, stderr=''))

    @mock.patch('monitor.scanner.IS_WINDOWS', False)
    def test_respuesta_correcta(self):
        salida = ('3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n'
                  'rtt min/avg/max/mdev = 1.100/2.500/4.000/1.200 ms\n')
        with self._run(salida):
            r = scanner.ping_host('10.0.0.1', count=3)
        self.assertEqual(r['alive'], True)
        self.assertEqual((r['latency'], r['jitter'], r['loss']), (2.5, 1.2, 0.0))

    @mock.patch('monitor.scanner.IS_WINDOWS', False)
    def test_sin_respuesta(self):
        with self._run('3 packets transmitted, 0 received, 100% packet loss, time 2040ms\n'):
            r = scanner.ping_host('10.0.0.1', count=3)
        self.assertEqual(r, {'alive': False, 'latency': None, 'jitter': None, 'loss': 100.0})

    @mock.patch('monitor.scanner.IS_WINDOWS', False)
    def test_tiempo_agotado(self):
        import subprocess
        with mock.patch('monitor.scanner.subprocess.run', side_effect=subprocess.TimeoutExpired('ping', 1)):
            r = scanner.ping_host('10.0.0.1')
        self.assertFalse(r['alive'])
        self.assertEqual(r['loss'], 100.0)


@mock.patch('monitor.tasks._send_fcm')
class AlertCooldownTests(TestCase):
    """No se repite una alerta igual (mismo dispositivo y tipo) antes de 15 minutos."""

    def setUp(self):
        self.device = Device.objects.create(ip='10.0.0.10')

    def test_el_tiempo_de_espera_es_de_15_minutos(self, _):
        self.assertEqual(tasks.ALERT_COOLDOWN, 15 * 60)

    def test_segunda_alerta_igual_se_omite(self, fcm):
        a1 = tasks._create_alert(self.device, 'critical', 'latency', 'primera')
        a2 = tasks._create_alert(self.device, 'critical', 'latency', 'segunda')
        self.assertIsNotNone(a1)
        self.assertIsNone(a2)
        self.assertEqual(Alert.objects.count(), 1)
        self.assertEqual(fcm.call_count, 1)

    def test_otro_tipo_de_alerta_si_se_crea(self, _):
        tasks._create_alert(self.device, 'critical', 'latency', 'latencia')
        self.assertIsNotNone(tasks._create_alert(self.device, 'warning', 'jitter', 'jitter'))

    def test_otro_dispositivo_si_genera_alerta(self, _):
        otro = Device.objects.create(ip='10.0.0.11')
        tasks._create_alert(self.device, 'critical', 'latency', 'a')
        self.assertIsNotNone(tasks._create_alert(otro, 'critical', 'latency', 'b'))

    def test_dentro_de_los_15_minutos_se_omite(self, _):
        a = tasks._create_alert(self.device, 'critical', 'latency', 'a')
        Alert.objects.filter(pk=a.pk).update(timestamp=timezone.now() - datetime.timedelta(minutes=14))
        self.assertIsNone(tasks._create_alert(self.device, 'critical', 'latency', 'b'))

    def test_pasados_15_minutos_se_vuelve_a_crear(self, _):
        a = tasks._create_alert(self.device, 'critical', 'latency', 'a')
        Alert.objects.filter(pk=a.pk).update(timestamp=timezone.now() - datetime.timedelta(minutes=16))
        self.assertIsNotNone(tasks._create_alert(self.device, 'critical', 'latency', 'b'))

    def test_alerta_resuelta_no_bloquea(self, _):
        a = tasks._create_alert(self.device, 'critical', 'latency', 'a')
        Alert.objects.filter(pk=a.pk).update(resolved=True)
        self.assertIsNotNone(tasks._create_alert(self.device, 'critical', 'latency', 'b'))

    def test_alerta_sin_dispositivo_nunca_se_omite(self, _):
        tasks._create_alert(None, 'info', 'other', 'a')
        self.assertIsNotNone(tasks._create_alert(None, 'info', 'other', 'b'))


def _ping(alive=True, latency=None, jitter=0.0, loss=0.0):
    if not alive:
        return {'alive': False, 'latency': None, 'jitter': None, 'loss': 100.0}
    return {'alive': True, 'latency': latency, 'jitter': jitter, 'loss': loss}


@mock.patch('monitor.tasks._send_fcm')
class ThresholdEvaluationTests(TestCase):
    """Evaluación de umbrales en quick_ping_cycle con ping simulado."""

    def setUp(self):
        self.device = Device.objects.create(ip='10.0.0.20', status='online')

    def ciclo(self, resultado, arp=None, tcp_abierto=False):
        sock = mock.Mock()
        sock.connect_ex.return_value = 0 if tcp_abierto else 1
        with mock.patch('monitor.scanner.ping_host', return_value=resultado), \
             mock.patch('monitor.scanner.get_mac_from_arp', return_value=arp), \
             mock.patch('socket.socket', return_value=sock):
            anomalia = tasks.quick_ping_cycle()
        self.device.refresh_from_db()
        return anomalia

    def tipos(self):
        return sorted(Alert.objects.values_list('alert_type', flat=True))

    def test_valores_normales_no_generan_alertas(self, _):
        self.assertFalse(self.ciclo(_ping(latency=20, jitter=2)))
        self.assertEqual(self.tipos(), [])
        self.assertEqual(self.device.status, 'online')
        self.assertEqual(MetricSnapshot.objects.get().qos_score, tasks.calculate_qos_score(20, 2, 0))

    def test_latencia_entre_aviso_y_critico_solo_cambia_estado(self, _):
        self.assertFalse(self.ciclo(_ping(latency=180)))
        self.assertEqual(self.device.status, 'warning')
        self.assertEqual(self.tipos(), [])

    def test_latencia_critica(self, _):
        self.assertTrue(self.ciclo(_ping(latency=250)))
        self.assertEqual(self.tipos(), ['latency'])
        self.assertEqual(Alert.objects.get().level, 'critical')
        self.assertEqual(self.device.status, 'warning')

    def test_umbral_personalizado_del_dispositivo(self, _):
        self.device.latency_critical = 50
        self.device.save()
        self.assertTrue(self.ciclo(_ping(latency=80)))
        self.assertEqual(self.tipos(), ['latency'])

    def test_perdida_de_paquetes(self, _):
        self.assertTrue(self.ciclo(_ping(latency=20, loss=10)))
        self.assertEqual(self.tipos(), ['loss'])

    def test_jitter_alto_es_advertencia_sin_anomalia(self, _):
        self.assertFalse(self.ciclo(_ping(latency=20, jitter=40)))
        self.assertEqual(self.tipos(), ['jitter'])
        self.assertEqual(Alert.objects.get().level, 'warning')

    def test_qos_minimo(self, _):
        self.device.qos_minimum = 95
        self.device.save()
        self.ciclo(_ping(latency=120))
        self.assertEqual(self.tipos(), ['qos'])

    def test_desconexion(self, fcm):
        self.assertTrue(self.ciclo(_ping(alive=False)))
        self.assertEqual(self.device.status, 'offline')
        self.assertEqual(self.tipos(), ['disconnect'])
        self.assertEqual(MetricSnapshot.objects.count(), 0)
        fcm.assert_called_once()

    def test_sin_ping_pero_presente_en_arp_no_se_desconecta(self, _):
        self.assertFalse(self.ciclo(_ping(alive=False), arp='aa:bb:cc:dd:ee:ff'))
        self.assertEqual(self.device.status, 'online')
        self.assertEqual(self.tipos(), [])

    def test_sin_ping_pero_con_puerto_tcp_abierto(self, _):
        self.assertFalse(self.ciclo(_ping(alive=False), tcp_abierto=True))
        self.assertEqual(self.device.status, 'online')

    def test_problema_persistente_no_repite_alerta(self, fcm):
        self.ciclo(_ping(latency=250))
        self.ciclo(_ping(latency=260))
        self.assertEqual(self.tipos(), ['latency'])
        self.assertEqual(fcm.call_count, 1)
