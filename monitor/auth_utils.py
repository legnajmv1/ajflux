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


def login_required_ajax(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            if request.path.startswith('/api/'):
                return JsonResponse(
                    {'error': 'No autenticado', 'redirect': '/login/'},
                    status=401
                )
            return redirect(f'/login/?next={request.path}')
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
