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
