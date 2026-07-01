from django.urls import path
from monitor import views

urlpatterns = [
    # ── Auth ──────────────────────────────────────
    path('login/',  views.login_view,  name='login'),
    path('logout/', views.logout_view, name='logout'),

    # ── Páginas ────────────────────────────────────
    path('',               views.overview,      name='overview'),
    path('dispositivos/',  views.dispositivos,  name='dispositivos'),
    path('metricas/',      views.metricas,      name='metricas'),
    path('topologia/',     views.topologia,     name='topologia'),
    path('reportes/',      views.reportes,      name='reportes'),
    path('configuracion/', views.configuracion, name='configuracion'),
    path('usuarios/',      views.usuarios_view, name='usuarios'),

    # ── API lectura ────────────────────────────────
    path('api/live/',                   views.api_live),
    path('api/dispositivos/',           views.api_devices),
    path('api/devices/',                views.api_devices),
    path('api/dispositivos/por-red/',   views.api_devices_by_network),  # ← nuevo
    path('api/devices/by-network/',     views.api_devices_by_network),  # ← nuevo
    path('api/metricas/',               views.api_metrics),
    path('api/metrics/',                views.api_metrics),
    path('api/topologia/',              views.api_topology),
    path('api/topology/',               views.api_topology),
    path('api/topologia/analizar/',     views.api_topology_analyze),
    path('api/topology/analyze/',       views.api_topology_analyze),
    path('api/reportes/',               views.api_reports),
    path('api/reports/',                views.api_reports),
    path('api/alertas/',                views.api_alerts),
    path('api/network/',                views.api_network_info),
    path('api/me/',                     views.api_me),

    # ── API solo admin ─────────────────────────────
    path('api/alertas/<int:alert_id>/resolver/', views.api_resolve_alert),
    path('api/alerts/<int:alert_id>/resolve/',   views.api_resolve_alert),
    path('api/scan/',                            views.api_scan),
    path('api/scan/status/',                     views.api_scan_status),
    path('api/umbrales/',                        views.api_thresholds),
    path('api/umbrales/<int:device_id>/guardar/',  views.api_save_threshold),
    path('api/umbrales/<int:device_id>/eliminar/', views.api_delete_threshold),
    path('api/monitor/estado/',                  views.api_monitor_status),

    # ── Gestión usuarios ───────────────────────────
    path('api/usuarios/',                         views.api_list_usuarios),
    path('api/usuarios/crear/',                   views.api_crear_usuario),
    path('api/usuarios/<int:user_id>/',           views.api_get_usuario),
    path('api/usuarios/<int:user_id>/editar/',    views.api_editar_usuario),
    path('api/usuarios/<int:user_id>/eliminar/',  views.api_eliminar_usuario),
    # aliases sin /api/
    path('usuarios/crear/',                   views.api_crear_usuario),
    path('usuarios/<int:user_id>/editar/',    views.api_editar_usuario),
    path('usuarios/<int:user_id>/eliminar/',  views.api_eliminar_usuario),

    # ── PDF ────────────────────────────────────────
    path('reportes/exportar-pdf/',                    views.exportar_pdf),
    path('reportes/exportar-pdf/<int:report_id>/',    views.exportar_pdf),
    path('api/app/login/',        views.api_app_login),
    path('api/app/register-fcm/', views.api_register_fcm),
]
