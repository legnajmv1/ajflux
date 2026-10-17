"""
AJFLUX — Autenticación por Token para clientes sin sesión (app móvil).

Las vistas de monitor/views.py son funciones Django planas que leen
request.user.is_authenticated / request.user.profile, poblado normalmente
por AuthenticationMiddleware a partir de la cookie de sesión. La app móvil
inicia sesión vía /api/app/login/ y recibe un Token de DRF en vez de una
sesión, así que sin este middleware request.user quedaría anónimo en todas
las vistas salvo las que ya parsean el header a mano (api_register_fcm).
"""
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token


class TokenAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', '')
        if auth.startswith('Token '):
            try:
                token = Token.objects.select_related('user').get(key=auth.split(' ', 1)[1])
                request.user = token.user
            except Token.DoesNotExist:
                request.user = AnonymousUser()
        return self.get_response(request)
