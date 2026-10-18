"""
AJFLUX — Decoradores y helpers de autenticación
Roles:
  admin    → acceso total
  operator → ver + exportar + escanear + configurar  (NO gestión usuarios)
  viewer   → ver + exportar PDF únicamente
"""
from functools import wraps
from django.shortcuts import redirect
from django.http import JsonResponse
from django.core.cache import cache

LOGIN_RATE_LIMIT  = 5
LOGIN_RATE_WINDOW = 15 * 60  # segundos


def get_client_ip(request):
    """CF-Connecting-IP si viene detrás de Cloudflare Tunnel; si no, REMOTE_ADDR."""
    return request.META.get('HTTP_CF_CONNECTING_IP') or request.META.get('REMOTE_ADDR', '0.0.0.0')


def is_login_rate_limited(request):
    return cache.get(f'login_attempts:{get_client_ip(request)}', 0) >= LOGIN_RATE_LIMIT


def register_failed_login(request):
    key = f'login_attempts:{get_client_ip(request)}'
    cache.set(key, cache.get(key, 0) + 1, LOGIN_RATE_WINDOW)


def reset_login_attempts(request):
    cache.delete(f'login_attempts:{get_client_ip(request)}')


def login_required_ajax(view_func):
    """Para endpoints de API/descarga: 401 JSON si no hay sesión o token válido."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'No autenticado', 'redirect': '/login/'}, status=401)
        return view_func(request, *args, **kwargs)
    return wrapper


def config_required(view_func):
    """admin u operator — para las vistas de escritura (resolver alertas, umbrales)."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'No autenticado'}, status=401)
        if not can_config(request.user):
            return JsonResponse({'error': 'Sin permisos de configuración'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            if request.path.startswith('/api/'):
                return JsonResponse({'error': 'No autenticado'}, status=401)
            return redirect(f'/login/?next={request.path}')
        try:
            if not request.user.profile.is_admin():
                if request.path.startswith('/api/'):
                    return JsonResponse({'error': 'Sin permisos de administrador'}, status=403)
                return redirect('/?sin_permiso=1')
        except Exception:
            if request.path.startswith('/api/'):
                return JsonResponse({'error': 'Sin permisos'}, status=403)
            return redirect('/?sin_permiso=1')
        return view_func(request, *args, **kwargs)
    return wrapper


def get_user_role(user):
    if not user.is_authenticated:
        return None
    try:
        return user.profile.role
    except Exception:
        return None


def is_admin(user):
    return get_user_role(user) == 'admin'


def is_operator_or_above(user):
    """admin o operator pueden escanear y configurar."""
    return get_user_role(user) in ('admin', 'operator')


def can_manage_users(user):
    return get_user_role(user) == 'admin'


def can_scan(user):
    return get_user_role(user) in ('admin', 'operator')


def can_export(user):
    return user.is_authenticated  # todos pueden exportar


def can_config(user):
    return get_user_role(user) in ('admin', 'operator')


def get_role_permissions(role):
    """Devuelve el dict de permisos para un rol dado."""
    return {
        'can_scan':   role in ('admin', 'operator'),
        'can_export': True,
        'can_config': role in ('admin', 'operator'),
        'can_users':  role == 'admin',
    }


def ensure_profile(user):
    from monitor.models import UserProfile
    try:
        return user.profile
    except Exception:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        role = 'admin' if User.objects.count() <= 1 else 'viewer'
        return UserProfile.objects.create(user=user, role=role)
