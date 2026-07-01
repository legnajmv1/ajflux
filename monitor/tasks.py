"""
AJFLUX — Tareas de Monitoreo en Background
===========================================
Ciclos internos:
  - Ping rápido     : cada PING_INTERVAL segundos (dispositivos conocidos)
  - Escaneo completo: cada AUTO_SCAN_INTERVAL segundos (escanea TODAS las interfaces en paralelo)
"""
import threading
import time
import json
import logging
import os
import platform

IS_WINDOWS = platform.system() == 'Windows'
logger = logging.getLogger(__name__)

_monitor_thread = None
_running        = False
_start_time     = 0

# ══════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ══════════════════════════════════════════════════════════

PING_INTERVAL        = 30    # segundos entre pings rápidos
AUTO_SCAN_INTERVAL   = 180   # segundos entre escaneos completos
DELETE_OFFLINE       = False # NO borrar offline — se limpian por antigüedad (ver below)
OFFLINE_GRACE_HOURS  = 1     # horas sin verse antes de eliminar un dispositivo
FIRST_SCAN_DELAY     = 10    # segundos antes del primer escaneo al arrancar

LATENCY_WARNING_MS = 150   # ms — estado warning
LATENCY_ALERT_MS   = 200   # ms — alerta crítica
LOSS_ALERT_PCT     = 5     # %  — alerta crítica de pérdida

# ══════════════════════════════════════════════════════════


def _send_fcm(alert):
    """Envía push a la app Android. Falla silenciosamente."""
    try:
        from monitor.fcm_utils import send_fcm_alert
        send_fcm_alert(alert)
    except Exception as e:
        logger.warning(f"[FCM] Error enviando push: {e}")


def calculate_qos_score(latency, jitter, loss) -> float:
    """Puntaje QoS 0-100 basado en modelo ITU-T G.107."""
    if latency is None:
        return 0.0

    if latency < 50:    lat_score = 100
    elif latency < 150: lat_score = 100 - (latency - 50) * 0.5
    elif latency < 300: lat_score = 50  - (latency - 150) * 0.3
    else:               lat_score = max(0, 5 - (latency - 300) * 0.01)

    jitter = jitter or 0
    if jitter < 10:    jit_score = 100
    elif jitter < 30:  jit_score = 100 - (jitter - 10) * 2
    else:              jit_score = max(0, 60 - (jitter - 30) * 1.5)

    loss = loss or 0
    if loss == 0:      loss_score = 100
    elif loss < 1:     loss_score = 90
    elif loss < 5:     loss_score = 80 - loss * 10
    else:              loss_score = max(0, 30 - loss * 3)

    return round(min(100, max(0, lat_score * 0.5 + jit_score * 0.3 + loss_score * 0.2)), 1)


def delete_offline_devices():
    """
    Elimina dispositivos que llevan más de OFFLINE_GRACE_HOURS sin verse.
    Esto preserva celulares que se van offline temporalmente (WiFi sleep, batería)
    y solo elimina equipos genuinamente desaparecidos.
    """
    from monitor.models import Device
    from django.utils import timezone
    import datetime
    cutoff = timezone.now() - datetime.timedelta(hours=OFFLINE_GRACE_HOURS)
    qs = Device.objects.filter(status='offline', last_seen__lt=cutoff)
    count = qs.count()
    if count > 0:
        qs.delete()
        logger.info(f"[SCAN] {count} dispositivo(s) offline > {OFFLINE_GRACE_HOURS}h eliminado(s)")
    return count


def scan_single_network(iface, progress_callback=None, progress_offset=0, progress_range=100) -> dict:
    from monitor.scanner import (
        arp_scan_network, ping_host, get_hostname,
        get_mac_from_arp, get_vendor_from_mac,
        detect_device_type, get_own_mac, nmap_scan_device,
    )
    from monitor.models import Device, MetricSnapshot, ScanReport, Alert
    from django.utils import timezone

    target_network = iface['network']
    gateway_ip     = iface.get('gateway')
    own_ip         = iface['ip']
    start_time     = time.time()

    logger.info(f"[SCAN] Iniciando red: {target_network} | Gateway: {gateway_ip} | Local: {own_ip}")

    def cb(pct, msg):
        if progress_callback:
            real_pct = progress_offset + int(pct * progress_range / 100)
            progress_callback(real_pct, f"[{target_network}] {msg}")

    cb(5, 'Escaneo ARP...')
    found_hosts = arp_scan_network(target_network)

    if not any(h['ip'] == own_ip for h in found_hosts):
        found_hosts.insert(0, {'ip': own_ip, 'mac': get_own_mac()})
    if gateway_ip and not any(h['ip'] == gateway_ip for h in found_hosts):
        found_hosts.insert(0, {'ip': gateway_ip, 'mac': get_mac_from_arp(gateway_ip) or ''})

    logger.info(f"[SCAN] {target_network} — {len(found_hosts)} hosts encontrados")

    devices_data = []
    online_count = 0

    for i, host in enumerate(found_hosts):
        ip  = host['ip']
        mac = host.get('mac', '') or get_mac_from_arp(ip) or ''

        pct = 10 + int((i / max(len(found_hosts), 1)) * 85)
        cb(pct, f'[{i+1}/{len(found_hosts)}] Analizando {ip}...')

        ping_result = ping_host(ip, count=3, timeout=2)
        hostname    = get_hostname(ip)
        vendor      = get_vendor_from_mac(mac)
        nmap_result = nmap_scan_device(ip)
        ports       = nmap_result.get('ports', [])
        services    = nmap_result.get('services', {})
        os_info     = nmap_result.get('os_info', 'Desconocido')
        os_accuracy = nmap_result.get('os_accuracy', 0)
        dev_type    = detect_device_type(hostname, mac, ports, os_info)
        is_gw       = (ip == gateway_ip)
        qos         = calculate_qos_score(
            ping_result.get('latency'),
            ping_result.get('jitter'),
            ping_result.get('loss'),
        )

        responded_to_arp = bool(host.get('mac', ''))

        if ping_result['alive']:
            online_count += 1
            status = 'warning' if (ping_result.get('latency') or 0) > LATENCY_WARNING_MS else 'online'
        elif responded_to_arp:
            online_count += 1
            status = 'online'
            ping_result['latency'] = ping_result['jitter'] = ping_result['loss'] = None
        else:
            status = 'offline'

        device, created = Device.objects.get_or_create(ip=ip)
        device.mac         = mac if mac else device.mac
        device.hostname    = hostname if hostname != ip else device.hostname
        device.vendor      = vendor
        device.device_type = dev_type
        device.status      = status
        device.is_gateway  = is_gw
        device.open_ports  = ports
        device.os_info     = os_info
        device.os_accuracy = os_accuracy
        device.network     = target_network
        device.last_seen   = timezone.now()
        device.save()

        if ping_result.get('latency') is not None:
            MetricSnapshot.objects.create(
                device=device,
                latency=ping_result.get('latency'),
                jitter=ping_result.get('jitter'),
                packet_loss=ping_result.get('loss', 0),
                qos_score=qos,
            )

        if not created and ping_result['alive']:
            lat  = ping_result.get('latency', 0) or 0
            loss = ping_result.get('loss', 0) or 0
            jit  = ping_result.get('jitter', 0) or 0

            if lat > device.get_latency_critical():
                _a = Alert.objects.create(device=device, level='critical',
                    message=f"Latencia crítica en {ip}: {lat:.0f}ms (límite: {device.get_latency_critical():.0f}ms)")
                _send_fcm(_a)
            elif lat > device.get_latency_warning():
                _a = Alert.objects.create(device=device, level='warning',
                    message=f"Latencia alta en {ip}: {lat:.0f}ms (límite: {device.get_latency_warning():.0f}ms)")
                _send_fcm(_a)
            if loss > device.get_loss_warning():
                _a = Alert.objects.create(device=device, level='critical',
                    message=f"Pérdida de paquetes en {ip}: {loss:.1f}% (límite: {device.get_loss_warning():.1f}%)")
                _send_fcm(_a)
            if jit > device.get_jitter_warning():
                _a = Alert.objects.create(device=device, level='warning',
                    message=f"Jitter alto en {ip}: {jit:.1f}ms (límite: {device.get_jitter_warning():.1f}ms)")
                _send_fcm(_a)
            if device.get_qos_minimum() > 0 and qos < device.get_qos_minimum():
                _a = Alert.objects.create(device=device, level='warning',
                    message=f"QoS bajo en {ip}: {qos:.0f}% (mínimo: {device.get_qos_minimum():.0f}%)")
                _send_fcm(_a)

        elif not created and not ping_result['alive']:
            if device.status != 'offline':
                _a = Alert.objects.create(device=device, level='warning',
                    message=f"Dispositivo {ip} ({hostname}) se desconectó")
                _send_fcm(_a)

        devices_data.append({
            'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor,
            'type': dev_type, 'status': status, 'is_gateway': is_gw,
            'os_info': os_info, 'os_accuracy': os_accuracy, 'network': target_network,
            'latency': ping_result.get('latency'), 'jitter': ping_result.get('jitter'),
            'loss': ping_result.get('loss'), 'qos': qos, 'ports': ports,
            'services': {str(k): v for k, v in services.items()},
        })

    duration  = time.time() - start_time
    latencies = [d['latency'] for d in devices_data if d['latency']]
    qos_list  = [d['qos']     for d in devices_data if d['qos']]

    ScanReport.objects.create(
        network=target_network,
        total_found=len(found_hosts),
        online_count=online_count,
        avg_latency=sum(latencies) / len(latencies) if latencies else None,
        avg_qos=sum(qos_list) / len(qos_list)       if qos_list  else None,
        scan_duration=duration,
        devices_json=json.dumps(devices_data),
    )

    cb(100, f'Listo — {len(found_hosts)} dispositivos en {duration:.1f}s')
    logger.info(f"[SCAN] {target_network} completo: {len(found_hosts)} dispositivos | {online_count} online | {duration:.1f}s")

    return {
        'network':  target_network,
        'total':    len(found_hosts),
        'online':   online_count,
        'duration': round(duration, 1),
        'devices':  devices_data,
    }


def run_scan(network=None, progress_callback=None) -> dict:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ajflux.settings')

    from monitor.scanner import get_local_interfaces

    if progress_callback:
        progress_callback(2, 'Limpiando dispositivos desconectados...')

    # Limpiar solo dispositivos offline por más de OFFLINE_GRACE_HOURS (no eliminar recientes)
    delete_offline_devices()

    if progress_callback:
        progress_callback(5, 'Detectando interfaces de red...')

    interfaces = get_local_interfaces()
    if not interfaces:
        return {'error': 'No se encontraron interfaces de red'}

    if network:
        interfaces = [i for i in interfaces if i['network'] == network] or interfaces[:1]

    logger.info(f"[SCAN] {len(interfaces)} interfaz(ces) detectada(s): {[i['network'] for i in interfaces]}")

    if progress_callback:
        progress_callback(8, f'{len(interfaces)} red(es) detectada(s) — iniciando escaneo paralelo...')

    results      = [None] * len(interfaces)
    threads      = []
    total_ranges = 92
    range_per    = total_ranges // max(len(interfaces), 1)

    def scan_thread(idx, iface):
        offset = 8 + idx * range_per
        results[idx] = scan_single_network(
            iface,
            progress_callback=progress_callback,
            progress_offset=offset,
            progress_range=range_per,
        )

    for idx, iface in enumerate(interfaces):
        t = threading.Thread(target=scan_thread, args=(idx, iface), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    all_devices  = []
    total_found  = 0
    total_online = 0

    for r in results:
        if r and 'devices' in r:
            all_devices  += r['devices']
            total_found  += r['total']
            total_online += r['online']

    if progress_callback:
        progress_callback(100, f'Listo — {total_found} dispositivos en {len(interfaces)} red(es)')

    return {
        'total':    total_found,
        'online':   total_online,
        'networks': len(interfaces),
        'results':  results,
        'devices':  all_devices,
    }


def quick_ping_cycle():
    """Ping rápido a todos los dispositivos conocidos."""
    from monitor.models import Device, MetricSnapshot, Alert
    from monitor.scanner import ping_host, get_mac_from_arp
    from django.utils import timezone
    import socket as _socket

    for device in Device.objects.filter(status__in=['online', 'warning']):
        try:
            result = ping_host(device.ip, count=3, timeout=2)
            qos    = calculate_qos_score(result.get('latency'), result.get('jitter'), result.get('loss'))

            if result['alive']:
                new_status = 'warning' if (result.get('latency') or 0) > LATENCY_WARNING_MS else 'online'
            else:
                tcp_alive = False
                for port in [80, 443, 22, 3389, 8080, 445]:
                    try:
                        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        if s.connect_ex((device.ip, port)) == 0:
                            tcp_alive = True
                            s.close()
                            break
                        s.close()
                    except Exception:
                        pass

                if tcp_alive:
                    new_status = device.status
                    result['latency'] = result['jitter'] = result['loss'] = None
                else:
                    try:
                        new_status = device.status if get_mac_from_arp(device.ip) else 'offline'
                        if new_status == device.status:
                            result['latency'] = result['jitter'] = result['loss'] = None
                    except Exception:
                        new_status = 'offline'

            if new_status != device.status and new_status == 'offline':
                _a = Alert.objects.create(device=device, level='critical',
                    message=f"{device.ip} ({device.hostname}) se desconectó [{device.network}]")
                _send_fcm(_a)

            if result['alive'] and new_status != 'offline':
                lat  = result.get('latency') or 0
                loss = result.get('loss') or 0
                jit  = result.get('jitter') or 0

                if lat and lat > device.get_latency_critical():
                    _a = Alert.objects.create(device=device, level='critical',
                        message=f"Latencia critica en {device.ip}: {lat:.0f}ms")
                    _send_fcm(_a)
                if loss and loss > device.get_loss_warning():
                    _a = Alert.objects.create(device=device, level='critical',
                        message=f"Perdida en {device.ip}: {loss:.1f}%")
                    _send_fcm(_a)
                if jit and jit > device.get_jitter_warning():
                    _a = Alert.objects.create(device=device, level='warning',
                        message=f"Jitter alto en {device.ip}: {jit:.1f}ms")
                    _send_fcm(_a)
                if device.get_qos_minimum() > 0 and qos < device.get_qos_minimum():
                    _a = Alert.objects.create(device=device, level='warning',
                        message=f"QoS bajo en {device.ip}: {qos:.0f}%")
                    _send_fcm(_a)

            device.status    = new_status
            device.last_seen = timezone.now()
            device.save(update_fields=['status', 'last_seen'])

            if result.get('latency') is not None:
                MetricSnapshot.objects.create(
                    device=device,
                    latency=result.get('latency'),
                    jitter=result.get('jitter'),
                    packet_loss=result.get('loss', 0),
                    qos_score=qos,
                )

        except Exception as e:
            logger.error(f"[PING] Error en {device.ip}: {e}")


def monitor_loop():
    """Loop principal: alterna entre ping rápido y escaneo completo."""
    global _running
    logger.info(
        f"[MONITOR] Iniciado — Ping cada {PING_INTERVAL}s | "
        f"Escaneo completo cada {AUTO_SCAN_INTERVAL}s ({AUTO_SCAN_INTERVAL // 60} min)"
    )

    last_ping = last_auto_scan = 0

    while _running:
        now = time.time()

        if now - last_auto_scan >= AUTO_SCAN_INTERVAL:
            if last_auto_scan == 0 and (now - _start_time) < FIRST_SCAN_DELAY:
                pass
            else:
                logger.info("[MONITOR] Iniciando escaneo automático de todas las redes...")
                try:
                    result = run_scan()
                    last_auto_scan = last_ping = now
                    if result:
                        logger.info(
                            f"[MONITOR] Escaneo completado — "
                            f"{result.get('total', 0)} dispositivos en "
                            f"{result.get('networks', 1)} red(es), "
                            f"{result.get('online', 0)} online"
                        )
                except Exception as e:
                    logger.error(f"[MONITOR] Error en escaneo automático: {e}")
                    last_auto_scan = now

        elif now - last_ping >= PING_INTERVAL:
            try:
                quick_ping_cycle()
                last_ping = now
            except Exception as e:
                logger.error(f"[MONITOR] Error en ping cycle: {e}")
                last_ping = now

        time.sleep(2)

    logger.info("[MONITOR] Detenido")


def start_background_monitor():
    global _monitor_thread, _running, _start_time
    if _monitor_thread and _monitor_thread.is_alive():
        return
    _running        = True
    _start_time     = time.time()
    _monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    _monitor_thread.start()
    logger.info("[MONITOR] Thread iniciado")


def stop_background_monitor():
    global _running
    _running = False