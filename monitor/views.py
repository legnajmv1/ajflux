"""
AJFLUX — Vistas Django
"""
import json
import threading
import time
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)
_scan_state = {"running": False, "progress": 0, "message": "", "last_result": None}


# ══════════════════════════════════════════════════════════
# PÁGINAS
# ══════════════════════════════════════════════════════════

def overview(request):
    if not request.user.is_authenticated:
        return redirect('/login/')
    return render(request, 'monitor/overview.html')

def dispositivos(request):
    if not request.user.is_authenticated:
        return redirect('/login/')
    return render(request, 'monitor/dispositivos.html')

def metricas(request):
    if not request.user.is_authenticated:
        return redirect('/login/')
    return render(request, 'monitor/metricas.html')

def topologia(request):
    if not request.user.is_authenticated:
        return redirect('/login/')
    return render(request, 'monitor/topologia.html')

def reportes(request):
    if not request.user.is_authenticated:
        return redirect('/login/')
    return render(request, 'monitor/reportes.html')

def configuracion(request):
    from monitor.auth_utils import is_admin
    if not request.user.is_authenticated:
        return redirect('/login/')
    if not is_admin(request.user):
        return redirect('/?sin_permiso=1')
    return render(request, 'monitor/configuracion.html')


# ══════════════════════════════════════════════════════════
# API — DISPOSITIVOS Y MÉTRICAS
# ══════════════════════════════════════════════════════════

@require_http_methods(["GET"])
def api_devices(request):
    from monitor.models import Device
    out = []
    for d in Device.objects.all().order_by("ip"):
        l = d.metrics.first()
        out.append({
            "id": d.id, "ip": d.ip, "mac": d.mac,
            "hostname": d.hostname or d.ip, "vendor": d.vendor,
            "type": d.device_type, "status": d.status, "is_gateway": d.is_gateway,
            "first_seen": d.first_seen.isoformat(), "last_seen": d.last_seen.isoformat(),
            "open_ports": d.open_ports,
            "latency": round(l.latency, 2)     if l and l.latency else None,
            "jitter":  round(l.jitter, 2)      if l and l.jitter  else None,
            "loss":    round(l.packet_loss, 1) if l               else None,
            "qos":     round(l.qos_score, 1)   if l               else None,
        })
    return JsonResponse({"devices": out, "ts": time.time()})


@require_http_methods(["GET"])
def api_devices_by_network(request):
    """Devuelve los dispositivos agrupados por red. Una lista por cada interfaz."""
    from monitor.models import Device
    from collections import defaultdict

    grupos = defaultdict(list)
    for d in Device.objects.all().order_by('network', 'ip'):
        l = d.metrics.first()
        red = d.network or 'Sin red'
        grupos[red].append({
            "id": d.id, "ip": d.ip, "mac": d.mac,
            "hostname": d.hostname or d.ip, "vendor": d.vendor,
            "type": d.device_type, "status": d.status, "is_gateway": d.is_gateway,
            "first_seen": d.first_seen.isoformat(), "last_seen": d.last_seen.isoformat(),
            "open_ports": d.open_ports,
            "latency": round(l.latency, 2)     if l and l.latency else None,
            "jitter":  round(l.jitter, 2)      if l and l.jitter  else None,
            "loss":    round(l.packet_loss, 1) if l               else None,
            "qos":     round(l.qos_score, 1)   if l               else None,
        })

    # Construir lista ordenada de redes con resumen
    redes = []
    for red, dispositivos in sorted(grupos.items()):
        online = sum(1 for d in dispositivos if d['status'] != 'offline')
        lats   = [d['latency'] for d in dispositivos if d['latency']]
        redes.append({
            'network':     red,
            'total':       len(dispositivos),
            'online':      online,
            'avg_latency': round(sum(lats) / len(lats), 1) if lats else None,
            'devices':     dispositivos,
        })

    return JsonResponse({'redes': redes, 'total_redes': len(redes), 'ts': time.time()})


@require_http_methods(["GET"])
def api_live(request):
    from monitor.models import Device, Alert
    devs = []
    for d in Device.objects.all().order_by("ip"):
        l = d.metrics.first()
        devs.append({
            "id": d.id, "ip": d.ip, "mac": d.mac,
            "hostname": d.hostname or d.ip, "vendor": d.vendor,
            "type": d.device_type, "status": d.status,
            "is_gateway": d.is_gateway, "open_ports": d.open_ports,
            "latency": round(l.latency, 2)     if l and l.latency else None,
            "jitter":  round(l.jitter, 2)      if l and l.jitter  else None,
            "loss":    round(l.packet_loss, 1) if l               else None,
            "qos":     round(l.qos_score, 1)   if l               else None,
        })
    alerts = [
        {
            "id": a.id, "level": a.level, "message": a.message,
            "timestamp": a.timestamp.isoformat(),
            "device_ip": a.device.ip if a.device else None,
        }
        for a in Alert.objects.filter(resolved=False).order_by("-timestamp")[:15]
    ]
    return JsonResponse({
        "devices": devs, "alerts": alerts,
        "scan": {
            "running":  _scan_state["running"],
            "progress": _scan_state["progress"],
            "message":  _scan_state["message"],
        },
        "ts": time.time(),
    })


@require_http_methods(["GET"])
def api_metrics(request):
    from monitor.models import Device
    did    = request.GET.get("device_id")
    mins   = int(request.GET.get("minutos", request.GET.get("minutes", 30)))
    cutoff = timezone.now() - timedelta(minutes=mins)
    qs     = Device.objects.filter(status__in=["online", "warning"])
    if did:
        qs = qs.filter(id=did)
    metrics = {}
    for d in qs:
        snaps = list(d.metrics.filter(timestamp__gte=cutoff).order_by("timestamp")[:120])
        metrics[d.id] = {
            "ip": d.ip, "hostname": d.hostname or d.ip,
            "history": [
                {
                    "ts":      s.timestamp.isoformat(),
                    "latency": round(s.latency, 2)     if s.latency else None,
                    "jitter":  round(s.jitter, 2)      if s.jitter  else None,
                    "loss":    round(s.packet_loss, 1),
                    "qos":     round(s.qos_score, 1),
                }
                for s in snaps
            ],
        }
    return JsonResponse({"metrics": metrics})


@require_http_methods(["GET"])
def api_topology(request):
    from monitor.models import Device
    from monitor.scanner import build_smart_topology
    import socket
    devs = list(Device.objects.all().values("ip", "hostname", "device_type", "mac", "vendor", "status", "is_gateway"))
    gw   = next((d for d in devs if d["is_gateway"]), None)
    try:   own_ip = socket.gethostbyname(socket.gethostname())
    except: own_ip = "127.0.0.1"
    device_list = [{"ip": d["ip"], "hostname": d["hostname"], "type": d["device_type"],
                    "mac": d["mac"], "vendor": d["vendor"], "status": d["status"]} for d in devs]
    return JsonResponse({"topology": build_smart_topology(device_list, gw["ip"] if gw else None, own_ip)})


@require_http_methods(["GET"])
def api_topology_analyze(request):
    from monitor.models import Device
    from monitor.scanner import detect_intermediary_devices, classify_topology
    import socket
    devs = list(Device.objects.all().values("ip", "hostname", "device_type", "mac", "vendor", "status", "is_gateway"))
    gw   = next((d for d in devs if d["is_gateway"]), None)
    try:   own_ip = socket.gethostbyname(socket.gethostname())
    except: own_ip = "127.0.0.1"
    device_list    = [{"ip": d["ip"], "hostname": d["hostname"], "type": d["device_type"],
                       "mac": d["mac"], "vendor": d["vendor"], "status": d["status"]} for d in devs]
    gw_ip          = gw["ip"] if gw else None
    intermediaries = detect_intermediary_devices(device_list, gw_ip, own_ip)
    return JsonResponse({"analysis": classify_topology(device_list, gw_ip, own_ip, intermediaries)})


@require_http_methods(["GET"])
def api_reports(request):
    from monitor.models import ScanReport
    return JsonResponse({"reports": [
        {
            "id": r.id, "timestamp": r.timestamp.isoformat(),
            "network": r.network, "total_found": r.total_found,
            "online_count": r.online_count,
            "avg_latency":   round(r.avg_latency, 1)  if r.avg_latency else None,
            "avg_qos":       round(r.avg_qos, 1)      if r.avg_qos     else None,
            "scan_duration": round(r.scan_duration, 1),
            "devices":       r.devices_snapshot,
        }
        for r in ScanReport.objects.all()[:50]
    ]})


@require_http_methods(["GET"])
def api_alerts(request):
    from monitor.models import Alert
    return JsonResponse({"alerts": [
        {
            "id": a.id, "level": a.level, "message": a.message,
            "timestamp": a.timestamp.isoformat(),
            "device_ip": a.device.ip if a.device else None,
        }
        for a in Alert.objects.filter(resolved=False).order_by("-timestamp")[:50]
    ]})


@csrf_exempt
@require_http_methods(["POST"])
def api_resolve_alert(request, alert_id):
    from monitor.models import Alert
    Alert.objects.filter(id=alert_id).update(resolved=True)
    return JsonResponse({"ok": True})


@csrf_exempt
@require_http_methods(["POST"])
def api_scan(request):
    from monitor.auth_utils import can_scan as _can_scan
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'No autenticado'}, status=401)
    if not _can_scan(request.user):
        return JsonResponse({'error': 'Sin permisos para escanear'}, status=403)
    global _scan_state
    if _scan_state["running"]:
        return JsonResponse({"ok": False, "msg": "Escaneo ya en progreso"})
    from monitor.tasks import run_scan
    def cb(p, m):
        _scan_state["progress"] = p
        _scan_state["message"]  = m
    def go():
        global _scan_state
        _scan_state.update({"running": True, "progress": 0, "message": "Iniciando..."})
        try:
            data = json.loads(request.body) if request.body else {}
            _scan_state["last_result"] = run_scan(network=data.get("network"), progress_callback=cb)
        except Exception as e:
            logger.error(f"Scan error: {e}")
        finally:
            _scan_state["running"]  = False
            _scan_state["progress"] = 100
    threading.Thread(target=go, daemon=True).start()
    return JsonResponse({"ok": True, "msg": "Escaneo iniciado"})


@require_http_methods(["GET"])
def api_scan_status(request):
    return JsonResponse(_scan_state)


@require_http_methods(["GET"])
def api_network_info(request):
    from monitor.scanner import get_local_interfaces
    try:
        return JsonResponse({"interfaces": get_local_interfaces()})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


# ══════════════════════════════════════════════════════════
# API — UMBRALES
# ══════════════════════════════════════════════════════════

@require_http_methods(["GET"])
def api_thresholds(request):
    from monitor.models import Device
    from monitor.tasks import LATENCY_WARNING_MS, LATENCY_ALERT_MS, LOSS_ALERT_PCT
    result = []
    for d in Device.objects.all().order_by('ip'):
        has_custom = any([
            d.latency_warning  is not None,
            d.latency_critical is not None,
            d.jitter_warning   is not None,
            d.loss_warning     is not None,
            d.qos_minimum      is not None,
        ])
        result.append({
            'device_id':        d.id,
            'ip':               d.ip,
            'hostname':         d.hostname or d.ip,
            'type':             d.device_type,
            'status':           d.status,
            'latency_warning':  d.latency_warning,
            'latency_critical': d.latency_critical,
            'jitter_warning':   d.jitter_warning,
            'loss_warning':     d.loss_warning,
            'qos_minimum':      d.qos_minimum,
            'notes':            d.threshold_notes,
            'has_custom':       has_custom,
        })
    return JsonResponse({
        'thresholds': result,
        'globals': {
            'latency_warning':  LATENCY_WARNING_MS,
            'latency_critical': LATENCY_ALERT_MS,
            'loss_warning':     LOSS_ALERT_PCT,
            'jitter_warning':   30,
        },
    })


@csrf_exempt
@require_http_methods(["POST"])
def api_save_threshold(request, device_id):
    from monitor.models import Device
    try:
        device = Device.objects.get(id=device_id)
    except Device.DoesNotExist:
        return JsonResponse({'error': 'Dispositivo no encontrado'}, status=404)
    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    def parse_float(val):
        try:
            v = float(val)
            return v if v > 0 else None
        except (TypeError, ValueError):
            return None

    device.latency_warning  = parse_float(data.get('latency_warning'))
    device.latency_critical = parse_float(data.get('latency_critical'))
    device.jitter_warning   = parse_float(data.get('jitter_warning'))
    device.loss_warning     = parse_float(data.get('loss_warning'))
    device.qos_minimum      = parse_float(data.get('qos_minimum'))
    device.threshold_notes  = str(data.get('notes', ''))[:500]
    device.save(update_fields=[
        'latency_warning', 'latency_critical', 'jitter_warning',
        'loss_warning', 'qos_minimum', 'threshold_notes',
    ])
    return JsonResponse({'ok': True, 'device_ip': device.ip})


@csrf_exempt
@require_http_methods(["DELETE"])
def api_delete_threshold(request, device_id):
    from monitor.models import Device
    Device.objects.filter(id=device_id).update(
        latency_warning=None, latency_critical=None,
        jitter_warning=None,  loss_warning=None,
        qos_minimum=None,     threshold_notes='',
    )
    return JsonResponse({'ok': True})


@require_http_methods(["GET"])
def api_monitor_status(request):
    from monitor.models import ScanReport
    from monitor.tasks import (PING_INTERVAL, AUTO_SCAN_INTERVAL, DELETE_OFFLINE,
                                FIRST_SCAN_DELAY, LATENCY_WARNING_MS, LATENCY_ALERT_MS, LOSS_ALERT_PCT)
    last_scan    = ScanReport.objects.first()
    next_scan_in = None
    if last_scan:
        elapsed      = (timezone.now() - last_scan.timestamp).total_seconds()
        next_scan_in = max(0, int(AUTO_SCAN_INTERVAL - elapsed))
    return JsonResponse({
        'ping_interval':      PING_INTERVAL,
        'scan_interval':      AUTO_SCAN_INTERVAL,
        'scan_interval_min':  AUTO_SCAN_INTERVAL // 60,
        'delete_offline':     DELETE_OFFLINE,
        'first_scan_delay':   FIRST_SCAN_DELAY,
        'latency_warning_ms': LATENCY_WARNING_MS,
        'latency_alert_ms':   LATENCY_ALERT_MS,
        'loss_alert_pct':     LOSS_ALERT_PCT,
        'last_scan':          last_scan.timestamp.isoformat() if last_scan else None,
        'last_scan_network':  last_scan.network               if last_scan else None,
        'last_scan_found':    last_scan.total_found           if last_scan else 0,
        'next_scan_in_sec':   next_scan_in,
    })


# ══════════════════════════════════════════════════════════
# EXPORTACIÓN PDF
# ══════════════════════════════════════════════════════════

@require_http_methods(["GET"])
def exportar_pdf(request, report_id=None):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer,
            Table, TableStyle, HRFlowable, PageBreak
        )
        from reportlab.lib.enums import TA_CENTER
        from io import BytesIO
        from monitor.models import Device, ScanReport
        from monitor.scanner import get_local_interfaces
        import socket

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
            leftMargin=1.5*cm, rightMargin=1.5*cm,
            topMargin=2*cm, bottomMargin=2*cm, title="Reporte AJFLUX QoS")

        AZUL = colors.HexColor("#0068b5")
        AL   = colors.HexColor("#a2c9ff")
        F2   = colors.HexColor("#1d2027")
        F3   = colors.HexColor("#272a31")
        B    = colors.white
        G    = colors.HexColor("#8c919d")
        G2   = colors.HexColor("#c2c6d4")
        NA   = colors.HexColor("#ffb68c")
        RJ   = colors.HexColor("#ffb4ab")

        SS = getSampleStyleSheet()
        def st(n, **k):
            return ParagraphStyle(n+"_x", parent=SS.get(n, SS["Normal"]), **k)

        sT   = st("Title",  fontSize=26, textColor=AL, fontName="Helvetica-Bold", spaceAfter=4)
        sSub = st("Normal", fontSize=9,  textColor=G,  fontName="Helvetica", spaceAfter=2)
        sH2  = st("Normal", fontSize=13, textColor=AL, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=7)
        sN   = st("Normal", fontSize=8.5, textColor=G2, fontName="Helvetica", spaceAfter=4)
        sCtr = st("Normal", fontSize=8,  textColor=G,  fontName="Helvetica", alignment=TA_CENTER)

        cLat = lambda v: G if not v else AL if v < 50 else NA if v < 150 else RJ
        cQos = lambda v: G if v is None else AL if v >= 80 else NA if v >= 60 else RJ

        fL = lambda v: f"{v:.0f} ms" if v else "—"
        fJ = lambda v: f"{v:.1f} ms" if v else "—"
        fP = lambda v: f"{v:.1f}%"   if v is not None else "—"
        fQ = lambda v: f"{v:.0f}%"   if v is not None else "—"

        now_s = timezone.now().strftime("%d/%m/%Y %H:%M:%S")
        try:   own = socket.gethostbyname(socket.gethostname())
        except: own = "—"

        story = [
            Paragraph("REPORTE AJFLUX", sT),
            Paragraph(f"Reporte generado: {now_s}", sSub),
            Spacer(1, .3*cm),
            HRFlowable(width="100%", thickness=1, color=AZUL, spaceAfter=10),
        ]

        story.append(Paragraph("Información de Red", sH2))
        try:
            ifaces = get_local_interfaces()
            rows = [["Interfaz", "IP", "Máscara", "Red", "Gateway"]]
            for i in ifaces:
                rows.append([i.get("name","—"), i.get("ip","—"), i.get("netmask","—"),
                              i.get("network","—"), i.get("gateway","—") or "—"])
            t = Table(rows, colWidths=[3*cm, 3.5*cm, 3.5*cm, 4*cm, 3.5*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0),  AZUL), ("TEXTCOLOR",(0,0),(-1,0),B),
                ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [F2,F3]), ("TEXTCOLOR",(0,1),(-1,-1),G2),
                ("GRID",          (0,0),(-1,-1), .3,F3), ("PADDING",(0,0),(-1,-1),5),
                ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
            ]))
            story.append(t)
        except Exception:
            story.append(Paragraph("No se pudo obtener info de interfaces.", sN))
        story.append(Spacer(1, .4*cm))

        devs = list(Device.objects.all().order_by("ip"))
        on   = [d for d in devs if d.status != "offline"]

        story.append(Paragraph("Dispositivos en la Red", sH2))
        story.append(Paragraph(
            f"Total: {len(devs)} dispositivos — {len(on)} en línea · {len(devs)-len(on)} desconectados", sN))

        if devs:
            rows = [["IP", "Hostname", "MAC", "Estado", "Latencia", "Jitter", "Pérdida", "QoS"]]
            for d in devs:
                l    = d.metrics.first()
                st_s = "En línea" if d.status=="online" else "Alerta" if d.status=="warning" else "Desconectado"
                rows.append([d.ip, (d.hostname or d.ip)[:22], d.mac or "—", st_s,
                              fL(l.latency if l else None), fJ(l.jitter if l else None),
                              fP(l.packet_loss if l else None), fQ(l.qos_score if l else None)])
            t = Table(rows, colWidths=[2.5*cm,4*cm,3.5*cm,2.5*cm,2*cm,2*cm,1.8*cm,1.8*cm], repeatRows=1)
            sty = [
                ("BACKGROUND",(0,0),(-1,0),AZUL),("TEXTCOLOR",(0,0),(-1,0),B),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[F2,F3]),("TEXTCOLOR",(0,1),(-1,-1),G2),
                ("GRID",(0,0),(-1,-1),.3,F3),("PADDING",(0,0),(-1,-1),4),
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(3,0),(-1,-1),"CENTER"),
            ]
            for ri, d in enumerate(devs, 1):
                l  = d.metrics.first()
                sc = AL if d.status=="online" else NA if d.status=="warning" else RJ
                sty += [("TEXTCOLOR",(3,ri),(3,ri),sc),("FONTNAME",(3,ri),(3,ri),"Helvetica-Bold")]
                if l:
                    sty += [("TEXTCOLOR",(4,ri),(4,ri),cLat(l.latency)),
                             ("TEXTCOLOR",(7,ri),(7,ri),cQos(l.qos_score))]
            t.setStyle(TableStyle(sty))
            story.append(t)

        story.append(PageBreak())
        story.append(Paragraph("Métricas de Calidad de Servicio (QoS)", sH2))
        story.append(Paragraph(
            "Latencia óptima < 50ms · Jitter < 10ms · Sin pérdida = QoS 100% (modelo ITU-T G.107)", sN))
        story.append(Spacer(1, .3*cm))

        if on:
            rows = [["Dispositivo","IP","Latencia","Jitter","Paq. Perdidos","QoS","Evaluación"]]
            for d in on:
                l   = d.metrics.first()
                qos = l.qos_score if l else None
                ev  = "—" if qos is None else "Excelente" if qos>=90 else "Bueno" if qos>=70 else "Regular" if qos>=50 else "Crítico"
                rows.append([(d.hostname or d.ip)[:20], d.ip,
                              fL(l.latency if l else None), fJ(l.jitter if l else None),
                              fP(l.packet_loss if l else None), fQ(qos), ev])
            t = Table(rows, colWidths=[4*cm,3*cm,2.5*cm,2.5*cm,2.8*cm,2.2*cm,2.5*cm], repeatRows=1)
            sty = [
                ("BACKGROUND",(0,0),(-1,0),AZUL),("TEXTCOLOR",(0,0),(-1,0),B),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8.5),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[F2,F3]),("TEXTCOLOR",(0,1),(-1,-1),G2),
                ("GRID",(0,0),(-1,-1),.3,F3),("PADDING",(0,0),(-1,-1),5),
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(2,0),(-1,-1),"CENTER"),
            ]
            for ri, d in enumerate(on, 1):
                l = d.metrics.first()
                if l:
                    sty += [("TEXTCOLOR",(2,ri),(2,ri),cLat(l.latency)),
                             ("TEXTCOLOR",(5,ri),(5,ri),cQos(l.qos_score)),
                             ("FONTNAME",(5,ri),(5,ri),"Helvetica-Bold")]
            t.setStyle(TableStyle(sty))
            story.append(t)

        story += [
            Spacer(1, .5*cm),
            HRFlowable(width="100%", thickness=.5, color=F3),
            Spacer(1, .2*cm),
            Paragraph(f"AJFLUX Monitoreo de Red · Generado el {now_s} · {own}", sCtr),
        ]

        doc.build(story)
        buf.seek(0)
        ts_str = timezone.now().strftime('%Y%m%d-%H%M%S')
        resp   = HttpResponse(buf.read(), content_type="application/pdf")
        resp["Content-Disposition"] = f'attachment; filename="ajflux-reporte-{ts_str}.pdf"'
        return resp

    except ImportError:
        return HttpResponse("Error: instala reportlab con: pip install reportlab",
                            content_type="text/plain", status=500)
    except Exception as e:
        logger.error(f"PDF error: {e}")
        return HttpResponse(f"Error: {e}", content_type="text/plain", status=500)


# ══════════════════════════════════════════════════════════
# AUTENTICACIÓN
# ══════════════════════════════════════════════════════════

def login_view(request):
    from django.contrib.auth import authenticate, login
    from monitor.auth_utils import ensure_profile
    if request.user.is_authenticated:
        return redirect('/')
    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            ensure_profile(user)
            return redirect(request.POST.get('next') or '/')
        error = 'Usuario o contraseña incorrectos'
    return render(request, 'monitor/login.html', {'error': error})


def logout_view(request):
    from django.contrib.auth import logout
    logout(request)
    return redirect('/login/')


# ══════════════════════════════════════════════════════════
# GESTIÓN DE USUARIOS
# ══════════════════════════════════════════════════════════

def usuarios_view(request):
    from monitor.auth_utils import is_admin
    from monitor.models import UserProfile
    from django.contrib.auth import get_user_model
    if not request.user.is_authenticated:
        return redirect('/login/')
    if not is_admin(request.user):
        return redirect('/?sin_permiso=1')

    User = get_user_model()
    users_data = []
    for u in User.objects.all().order_by('date_joined'):
        try:
            role         = u.profile.role
            role_display = u.profile.get_role_display()
            created_at   = u.profile.created_at.strftime('%d/%m/%Y')
        except Exception:
            role, role_display = 'viewer', 'Usuario Normal'
            created_at = u.date_joined.strftime('%d/%m/%Y')
        users_data.append({
            'id': u.id, 'username': u.username, 'fullname': u.get_full_name(),
            'role': role, 'role_display': role_display, 'created_at': created_at,
        })

    return render(request, 'monitor/usuarios.html', {
        'users': users_data,
        'admin_perms': [
            'Ver dispositivos y métricas', 'Ver topología de red',
            'Ver reportes y exportar PDF', 'Escanear la red',
            'Configurar umbrales de alerta', 'Gestionar usuarios', 'Resolver alertas',
        ],
        'viewer_perms': [
            {'label': 'Ver dispositivos y métricas',  'allowed': True},
            {'label': 'Ver topología de red',          'allowed': True},
            {'label': 'Ver reportes y exportar PDF',   'allowed': True},
            {'label': 'Escanear la red',               'allowed': False},
            {'label': 'Configurar umbrales',           'allowed': False},
            {'label': 'Gestionar usuarios',            'allowed': False},
            {'label': 'Resolver alertas',              'allowed': False},
        ],
    })


@require_http_methods(['GET'])
def api_list_usuarios(request):
    """GET /api/usuarios/ — lista todos los usuarios (solo admin)."""
    from monitor.auth_utils import is_admin, get_role_permissions
    from django.contrib.auth import get_user_model
    if not request.user.is_authenticated or not is_admin(request.user):
        return JsonResponse({'error': 'Sin permisos'}, status=403)
    User = get_user_model()
    users = []
    for u in User.objects.all().order_by('date_joined'):
        try:
            role = u.profile.role
        except Exception:
            role = 'viewer'
        perms = get_role_permissions(role)
        users.append({
            'id': u.id, 'username': u.username,
            'first_name': u.first_name, 'last_name': u.last_name,
            'email': u.email, 'is_active': u.is_active,
            'role': role, **perms,
        })
    return JsonResponse({'users': users})


@require_http_methods(['GET'])
def api_get_usuario(request, user_id):
    """GET /api/usuarios/<id>/ — datos de un usuario (solo admin)."""
    from monitor.auth_utils import is_admin, get_role_permissions
    from django.contrib.auth import get_user_model
    if not request.user.is_authenticated or not is_admin(request.user):
        return JsonResponse({'error': 'Sin permisos'}, status=403)
    User = get_user_model()
    try:
        u = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'No encontrado'}, status=404)
    try:
        role = u.profile.role
    except Exception:
        role = 'viewer'
    perms = get_role_permissions(role)
    return JsonResponse({
        'id': u.id, 'username': u.username,
        'first_name': u.first_name, 'last_name': u.last_name,
        'email': u.email, 'is_active': u.is_active,
        'role': role, **perms,
    })


def api_crear_usuario(request):
    from monitor.auth_utils import is_admin
    from monitor.models import UserProfile
    from django.contrib.auth import get_user_model
    if not request.user.is_authenticated or not is_admin(request.user):
        return JsonResponse({'error': 'Sin permisos'}, status=403)
    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    User      = get_user_model()
    username  = data.get('username', '').strip()
    password  = data.get('password', '')
    # Aceptar both 'first_name' (template nuevo) y 'fullname' (legado)
    first_name = data.get('first_name', data.get('fullname', '')).strip()
    role      = data.get('role', 'viewer')
    email     = data.get('email', '').strip()
    is_active = data.get('is_active', True)

    if not username:
        return JsonResponse({'error': 'El nombre de usuario es obligatorio'})
    if not password or len(password) < 6:
        return JsonResponse({'error': 'La contraseña debe tener al menos 6 caracteres'})
    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': f'El usuario "{username}" ya existe'})
    if role not in ('admin', 'operator', 'viewer'):
        role = 'viewer'

    parts = first_name.split(' ', 1)
    user = User.objects.create_user(
        username=username, password=password, email=email,
        first_name=parts[0], last_name=parts[1] if len(parts) > 1 else '',
        is_active=is_active,
    )
    UserProfile.objects.create(user=user, role=role)
    return JsonResponse({'ok': True, 'username': username})


@csrf_exempt
@require_http_methods(['POST'])
def api_editar_usuario(request, user_id):
    from monitor.auth_utils import is_admin
    from monitor.models import UserProfile
    from django.contrib.auth import get_user_model
    if not request.user.is_authenticated or not is_admin(request.user):
        return JsonResponse({'error': 'Sin permisos'}, status=403)

    User = get_user_model()
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=404)
    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    first_name = data.get('first_name', data.get('fullname', '')).strip()
    role       = data.get('role', 'viewer')
    password   = data.get('password', '')
    email      = data.get('email', '').strip()
    is_active  = data.get('is_active', True)

    if first_name:
        parts = first_name.split(' ', 1)
        user.first_name = parts[0]
        user.last_name  = parts[1] if len(parts) > 1 else ''
    if email:
        user.email = email
    user.is_active = is_active
    if password:
        if len(password) < 6:
            return JsonResponse({'error': 'La contraseña debe tener al menos 6 caracteres'})
        user.set_password(password)
    user.save()

    profile, _ = UserProfile.objects.get_or_create(user=user)
    if role in ('admin', 'operator', 'viewer'):
        profile.role = role
    profile.save()
    return JsonResponse({'ok': True})


@csrf_exempt
@require_http_methods(['DELETE'])
def api_eliminar_usuario(request, user_id):
    from monitor.auth_utils import is_admin
    from django.contrib.auth import get_user_model
    if not request.user.is_authenticated or not is_admin(request.user):
        return JsonResponse({'error': 'Sin permisos'}, status=403)
    if user_id == request.user.id:
        return JsonResponse({'error': 'No puedes eliminarte a ti mismo'})
    User = get_user_model()
    try:
        User.objects.get(id=user_id).delete()
        return JsonResponse({'ok': True})
    except User.DoesNotExist:
        return JsonResponse({'error': 'Usuario no encontrado'}, status=404)


@require_http_methods(['GET'])
def api_me(request):
    from monitor.auth_utils import get_user_role, get_role_permissions
    if not request.user.is_authenticated:
        return JsonResponse({'authenticated': False})
    role  = get_user_role(request.user)
    perms = get_role_permissions(role or 'viewer')
    return JsonResponse({
        'authenticated':  True,
        'username':       request.user.username,
        'fullname':       request.user.get_full_name(),
        'role':           role,
        'is_admin':       role == 'admin',
        'is_operator':    role == 'operator',
        **perms,
    })

from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token

@csrf_exempt
def api_app_login(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST requerido'}, status=405)
    try:
        data = json.loads(request.body)
        user = authenticate(username=data['username'], password=data['password'])
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            role = getattr(getattr(user, 'profile', None), 'role', 'viewer')
            return JsonResponse({'token': token.key, 'username': user.username, 'role': role})
        return JsonResponse({'error': 'Credenciales inválidas'}, status=401)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def api_register_fcm(request):
    auth = request.META.get('HTTP_AUTHORIZATION', '')
    if auth.startswith('Token '):
        try:
            token = Token.objects.get(key=auth.split(' ')[1])
            user = token.user
            data = json.loads(request.body)
            profile = user.profile
            profile.fcm_token = data.get('fcm_token', '')
            profile.save()
            return JsonResponse({'ok': True})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'No autenticado'}, status=401)