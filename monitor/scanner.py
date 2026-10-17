"""
AJFLUX — Motor de Escaneo de Red v2.0
=====================================================
Herramientas utilizadas:
  - Scapy        : Escaneo ARP broadcast para descubrir dispositivos
  - python-nmap  : Análisis de puertos, servicios y sistema operativo
  - psutil       : Detección de interfaces de red del servidor
  - socket       : Ping TCP, resolución DNS de hostnames
  - subprocess   : Comando ping del SO para latencia/jitter/perdida
"""
import subprocess
import socket
import os
import re
import time
import threading
import platform
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)
IS_WINDOWS = platform.system() == 'Windows'

# ── Importaciones opcionales ─────────────────────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("[SCANNER] psutil no disponible")

try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    HAS_SCAPY = True
    logger.info("[SCANNER] Scapy activo — escaneo ARP broadcast")
except ImportError:
    HAS_SCAPY = False
    logger.warning("[SCANNER] Scapy no disponible — usando fallback")

try:
    import nmap as nmap_lib
    HAS_NMAP = True
    logger.info("[SCANNER] python-nmap activo — analisis de servicios")
except ImportError:
    HAS_NMAP = False
    logger.warning("[SCANNER] python-nmap no disponible — usando socket")


# ═══════════════════════════════════════════════════
# INTERFACES — psutil
# ═══════════════════════════════════════════════════

def get_local_interfaces() -> list:
    """
    Detecta interfaces de red usando psutil.
    psutil.net_if_addrs() devuelve IPs, mascaras y MACs.
    psutil.net_if_stats() devuelve velocidad y estado.
    """
    interfaces = []
    gateway = _get_gateway()

    if HAS_PSUTIL:
        stats = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            if IS_WINDOWS and iface in stats and not stats[iface].isup:
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask or '255.255.255.0'
                    if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                        try:
                            net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            interfaces.append({
                                'name': iface,
                                'ip': ip,
                                'netmask': netmask,
                                'network': str(net),
                                'gateway': gateway,
                                'speed': stats[iface].speed if iface in stats else 0,
                                'mtu': stats[iface].mtu if iface in stats else 1500,
                            })
                        except Exception:
                            pass
    else:
        _interfaces_fallback(interfaces, gateway)

    return interfaces


def _interfaces_fallback(interfaces: list, gateway: str):
    """Fallback sin psutil: ipconfig o ip addr."""
    if IS_WINDOWS:
        try:
            r = subprocess.run(['ipconfig'], capture_output=True, text=True,
                               encoding='utf-8', errors='replace',
                               creationflags=subprocess.CREATE_NO_WINDOW)
            cur = 'Ethernet'
            for line in r.stdout.splitlines():
                m = re.match(r'^(\S.+):$', line)
                if m:
                    cur = m.group(1).strip()
                ip_m = re.search(r'IPv4[^:]*:\s*([\d.]+)', line)
                if ip_m:
                    ip = ip_m.group(1)
                    if not ip.startswith('127.') and not ip.startswith('169.254.'):
                        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                        interfaces.append({'name': cur, 'ip': ip,
                                           'netmask': '255.255.255.0',
                                           'network': str(net), 'gateway': gateway,
                                           'speed': 0, 'mtu': 1500})
        except Exception:
            pass
    else:
        try:
            r = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
            cur = None
            for line in r.stdout.splitlines():
                m = re.match(r'^\d+: (\S+):', line)
                if m:
                    cur = m.group(1)
                m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if m and cur:
                    ip = m.group(1)
                    prefix = int(m.group(2))
                    if not ip.startswith('127.'):
                        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                        interfaces.append({'name': cur, 'ip': ip,
                                           'netmask': str(net.netmask),
                                           'network': str(net), 'gateway': gateway,
                                           'speed': 0, 'mtu': 1500})
        except Exception:
            pass


def _get_gateway() -> Optional[str]:
    """Obtiene el gateway por defecto."""
    if IS_WINDOWS:
        try:
            r = subprocess.run(
                ['powershell', '-Command',
                 '(Get-NetRoute -DestinationPrefix "0.0.0.0/0" | '
                 'Sort-Object RouteMetric | Select-Object -First 1).NextHop'],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW)
            gw = r.stdout.strip()
            if re.match(r'\d+\.\d+\.\d+\.\d+', gw):
                return gw
        except Exception:
            pass
        try:
            r = subprocess.run(['route', 'print', '0.0.0.0'],
                               capture_output=True, text=True, timeout=5,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            for line in r.stdout.splitlines():
                m = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    return m.group(1)
        except Exception:
            pass
    else:
        try:
            r = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if 'default' in line:
                    parts = line.split()
                    if 'via' in parts:
                        return parts[parts.index('via') + 1]
        except Exception:
            pass
    return None


def get_own_mac() -> str:
    """MAC de la interfaz principal via psutil."""
    if HAS_PSUTIL:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address
                    if mac and mac not in ('00:00:00:00:00:00', ''):
                        return mac
    return 'Unknown'


# ═══════════════════════════════════════════════════
# ESCANEO ARP — Scapy broadcast
# ═══════════════════════════════════════════════════

def arp_scan_scapy(network: str) -> list:
    """
    Escaneo ARP broadcast con Scapy.
    Timeout aumentado a 5s con 2 reintentos para capturar
    dispositivos móviles en modo ahorro de energía/WiFi sleep.
    """
    hosts = []
    try:
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=network)
        answered, _ = srp(pkt, timeout=5, retry=2, verbose=False)
        for sent, received in answered:
            hosts.append({
                'ip': received.psrc,
                'mac': received.hwsrc.lower(),
            })
        logger.info(f"[SCAPY] {len(hosts)} hosts en {network}")
    except PermissionError:
        logger.warning("[SCAPY] Sin permisos para ARP raw socket (necesita root/CAP_NET_RAW)")
    except Exception as e:
        logger.error(f"[SCAPY] Error: {e}")
    return hosts


def _read_arp_cache_linux(net_obj, seen: set) -> list:
    """Lee /proc/net/arp y devuelve hosts en la red indicada."""
    hosts = []
    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    ip  = parts[0]
                    mac = parts[3]
                    if mac != '00:00:00:00:00:00' and ip not in seen:
                        try:
                            if ipaddress.IPv4Address(ip) in net_obj:
                                hosts.append({'ip': ip, 'mac': mac})
                                seen.add(ip)
                        except Exception:
                            pass
    except Exception:
        pass
    return hosts


def _ping_sweep_subnet(host_list: list):
    """
    Envía pings a todos los hosts en paralelo para:
    1. Despertar dispositivos móviles en WiFi sleep
    2. Poblar la tabla ARP del kernel (/proc/net/arp)
    """
    threads = []
    for host in host_list:
        t = threading.Thread(target=_ping_sweep_worker, args=(str(host),), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=6)
    time.sleep(1.0)


def arp_scan_network(network: str) -> list:
    """
    Descubrimiento de red — estrategia combinada:
    1. Ping sweep paralelo (despierta celulares en WiFi sleep + llena ARP cache)
    2. Scapy ARP broadcast (captura MACs directamente)
    3. Leer /proc/net/arp (captura devices que respondieron ping pero no ARP broadcast)
    4. python-nmap / nmap CLI como fallback si Scapy no está disponible
    Los resultados de todos los métodos se fusionan por IP única.
    """
    hosts = []
    seen  = set()

    try:
        net_obj   = ipaddress.IPv4Network(network, strict=False)
        host_list = list(net_obj.hosts())[:254]
    except Exception:
        net_obj   = None
        host_list = []

    # Paso 1 — Ping sweep: despierta celulares y llena la tabla ARP del kernel
    if host_list and not IS_WINDOWS:
        logger.info(f"[SCAN] Ping sweep previo en {network} para despertar dispositivos...")
        _ping_sweep_subnet(host_list)
        # Leer ARP cache del kernel ANTES del scan Scapy
        if net_obj:
            for h in _read_arp_cache_linux(net_obj, seen):
                hosts.append(h)

    # Paso 2 — Scapy ARP broadcast (ahora los móviles ya están despiertos)
    if HAS_SCAPY:
        try:
            for h in arp_scan_scapy(network):
                if h['ip'] not in seen:
                    hosts.append(h)
                    seen.add(h['ip'])
                else:
                    # Actualizar MAC si estaba vacía en el cache
                    for existing in hosts:
                        if existing['ip'] == h['ip'] and not existing.get('mac'):
                            existing['mac'] = h['mac']
                            break
        except Exception as e:
            logger.warning(f"[SCAN] Scapy: {e}")

        # Leer ARP cache de nuevo después del scan Scapy (puede haber nuevas entradas)
        if net_obj and not IS_WINDOWS:
            for h in _read_arp_cache_linux(net_obj, seen):
                hosts.append(h)

        if hosts:
            logger.info(f"[SCAN] {len(hosts)} hosts totales (ping+ARP) en {network}")
            return hosts

    # Paso 3 — python-nmap como fallback (sin Scapy)
    if HAS_NMAP:
        try:
            nm = nmap_lib.PortScanner()
            nm.scan(hosts=network, arguments='-sn -T4 --host-timeout 5s')
            for host in nm.all_hosts():
                if host not in seen:
                    mac = nm[host].get('addresses', {}).get('mac', '').lower()
                    hosts.append({'ip': host, 'mac': mac})
                    seen.add(host)
            if hosts:
                return hosts
        except Exception as e:
            logger.warning(f"[SCAN] python-nmap: {e}")

    # Paso 4 — nmap CLI como último recurso
    nmap_paths = ['nmap']
    if IS_WINDOWS:
        nmap_paths += [r'C:\Program Files (x86)\Nmap\nmap.exe',
                       r'C:\Program Files\Nmap\nmap.exe']
    for nmap_cmd in nmap_paths:
        try:
            extra = {'creationflags': subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}
            r = subprocess.run(
                [nmap_cmd, '-sn', '-T4', '--host-timeout', '5s', network],
                capture_output=True, text=True, encoding='utf-8',
                errors='replace', timeout=120, **extra)
            cur_ip = None
            cur_mac = None
            for line in r.stdout.splitlines():
                ip_m = re.search(r'Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)\)?', line)
                if ip_m:
                    if cur_ip and cur_ip not in seen:
                        hosts.append({'ip': cur_ip, 'mac': cur_mac or ''})
                        seen.add(cur_ip)
                    cur_ip = ip_m.group(1)
                    cur_mac = None
                mac_m = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})', line)
                if mac_m:
                    cur_mac = mac_m.group(1).lower()
            if cur_ip and cur_ip not in seen:
                hosts.append({'ip': cur_ip, 'mac': cur_mac or ''})
                seen.add(cur_ip)
            if hosts:
                return hosts
        except Exception:
            continue

    # Paso 5 — Ping sweep + tabla ARP (Windows o sin ninguna herramienta)
    try:
        if not host_list and net_obj:
            host_list = list(net_obj.hosts())[:254]
        if host_list:
            threads = []
            for host in host_list:
                t = threading.Thread(target=_ping_sweep_worker, args=(str(host),), daemon=True)
                threads.append(t)
                t.start()
            for t in threads:
                t.join(timeout=6)
            time.sleep(1.0)

            if IS_WINDOWS and net_obj:
                hosts = _read_arp_windows(net_obj)
            elif net_obj:
                for h in _read_arp_cache_linux(net_obj, seen):
                    hosts.append(h)
    except Exception as e:
        logger.error(f"[SCAN] Ping sweep fallback: {e}")

    return hosts


def _ping_sweep_worker(ip_str: str):
    """Ping rápido para despertar dispositivos y llenar tabla ARP del kernel."""
    try:
        if IS_WINDOWS:
            subprocess.run(['ping', '-n', '2', '-w', '800', ip_str],
                           capture_output=True, timeout=3,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            # 2 pings, 2s timeout — suficiente para despertar móviles en WiFi sleep
            subprocess.run(['ping', '-c', '2', '-W', '2', '-q', ip_str],
                           capture_output=True, timeout=5)
    except Exception:
        pass


def _read_arp_windows(net_obj) -> list:
    hosts = []
    seen = set()
    try:
        r = subprocess.run(['arp', '-a'], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=5,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        for line in r.stdout.splitlines():
            m = re.search(
                r'(\d+\.\d+\.\d+\.\d+)\s+'
                r'([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:]'
                r'[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:]'
                r'[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})', line)
            if m:
                ip = m.group(1)
                mac = m.group(2).replace('-', ':').lower()
                if ip not in seen and not ip.endswith('.255'):
                    try:
                        if ipaddress.IPv4Address(ip) in net_obj:
                            hosts.append({'ip': ip, 'mac': mac})
                            seen.add(ip)
                    except Exception:
                        pass
    except Exception:
        pass
    return hosts


# ═══════════════════════════════════════════════════
# PING — subprocess (latencia / jitter / perdida)
# ═══════════════════════════════════════════════════

def ping_host(ip: str, count: int = 4, timeout: int = 2) -> dict:
    """
    Mide latencia real, jitter y packet loss
    ejecutando el comando ping del sistema operativo.
    Windows: ping -n count -w ms ip
    Linux:   ping -c count -W s -q ip
    """
    try:
        if IS_WINDOWS:
            cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), ip]
            extra = {'creationflags': subprocess.CREATE_NO_WINDOW}
        else:
            cmd = ['ping', '-c', str(count), '-W', str(timeout), '-q', ip]
            extra = {}

        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding='utf-8', errors='replace',
                           timeout=timeout * count + 8, **extra)
        output = r.stdout + r.stderr
        return _parse_windows_ping(output) if IS_WINDOWS else _parse_linux_ping(output)

    except subprocess.TimeoutExpired:
        return {'alive': False, 'latency': None, 'jitter': None, 'loss': 100.0}
    except Exception as e:
        logger.debug(f"[PING] {ip}: {e}")
        return {'alive': False, 'latency': None, 'jitter': None, 'loss': 100.0}


def _parse_windows_ping(output: str) -> dict:
    loss_m = re.search(r'\((\d+)%[^)]*\)', output)
    loss = float(loss_m.group(1)) if loss_m else 100.0
    if loss >= 100:
        return {'alive': False, 'latency': None, 'jitter': None, 'loss': 100.0}

    times_m = re.search(
        r'[Mm](?:ínimo|inimum)\s*=\s*(\d+)ms[^,]*,\s*'
        r'[Mm](?:áximo|aximum)\s*=\s*(\d+)ms[^,]*,\s*'
        r'[Mm](?:edia|ean|verage)\s*=\s*(\d+)ms', output)
    if times_m:
        rtt_min = float(times_m.group(1))
        rtt_max = float(times_m.group(2))
        rtt_avg = float(times_m.group(3))
        return {'alive': True, 'latency': round(rtt_avg, 2),
                'jitter': round((rtt_max - rtt_min) / 2, 2),
                'loss': round(loss, 1), 'min': rtt_min, 'max': rtt_max}

    individual = re.findall(
        r'[Tt]iempo[<=](\d+)ms|[Tt]ime[<=](\d+)ms|'
        r'tiempo<(\d+)ms|time<(\d+)ms', output)
    times = [float(next(g for g in grps if g)) for grps in individual]
    if times:
        avg = sum(times) / len(times)
        jitter = (max(times) - min(times)) / 2 if len(times) > 1 else 0
        return {'alive': True, 'latency': round(avg, 2),
                'jitter': round(jitter, 2), 'loss': round(loss, 1)}

    return {'alive': True, 'latency': 1.0, 'jitter': 0.0, 'loss': round(loss, 1)}


def _parse_linux_ping(output: str) -> dict:
    loss_m = re.search(r'(\d+)% packet loss', output)
    loss = float(loss_m.group(1)) if loss_m else 100.0
    rtt_m = re.search(r'rtt[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
    if rtt_m:
        return {'alive': loss < 100,
                'latency': round(float(rtt_m.group(2)), 2),
                'jitter': round(float(rtt_m.group(4)), 2),
                'loss': round(loss, 1),
                'min': float(rtt_m.group(1)), 'max': float(rtt_m.group(3))}
    return {'alive': loss < 100, 'latency': None, 'jitter': None, 'loss': round(loss, 1)}


# ═══════════════════════════════════════════════════
# NMAP — python-nmap (puertos, servicios, SO)
# ═══════════════════════════════════════════════════

def nmap_scan_device(ip: str) -> dict:
    """
    Analisis completo de un dispositivo con python-nmap.
    -sV: detecta versiones de servicios en puertos abiertos
    -O:  detecta el sistema operativo (solo con root/sudo)
    -T4: velocidad rapida
    """
    result = {
        'ports': [], 'services': {},
        'os_info': 'Desconocido', 'os_accuracy': 0,
    }

    if not HAS_NMAP:
        result['ports'] = scan_ports_socket(ip)
        return result

    base_args = '-sV -T4 --host-timeout 10s'
    os_args   = '-O --osscan-guess'

    try:
        nm = nmap_lib.PortScanner()
        try:
            nm.scan(ip, arguments=f'{base_args} {os_args}'.strip())
        except Exception:
            nm.scan(ip, arguments=base_args)

        if ip not in nm.all_hosts():
            return result

        host = nm[ip]

        # Puertos y servicios
        for proto in host.all_protocols():
            for port in host[proto].keys():
                info = host[proto][port]
                if info['state'] == 'open':
                    result['ports'].append(port)
                    result['services'][port] = {
                        'name': info.get('name', ''),
                        'product': info.get('product', ''),
                        'version': info.get('version', ''),
                        'extrainfo': info.get('extrainfo', ''),
                    }

        # Sistema operativo
        if 'osmatch' in host and host['osmatch']:
            best = host['osmatch'][0]
            result['os_info'] = best.get('name', 'Desconocido')
            result['os_accuracy'] = int(best.get('accuracy', 0))

        logger.info(f"[NMAP] {ip}: {len(result['ports'])} puertos, OS={result['os_info']}")

    except Exception as e:
        logger.error(f"[NMAP] {ip}: {e}")
        result['ports'] = scan_ports_socket(ip)

    return result


def scan_ports_socket(ip: str, ports: list = None) -> list:
    """
    Escaneo TCP con socket.connect_ex() como fallback.
    Retorna lista de puertos abiertos.
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143,
                 443, 445, 3306, 3389, 5900, 8080, 8443]
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports


def scan_ports(ip: str, ports: list = None) -> list:
    """Alias de scan_ports_socket para compatibilidad."""
    return scan_ports_socket(ip, ports)


# ═══════════════════════════════════════════════════
# HOSTNAME y MAC — socket / ARP
# ═══════════════════════════════════════════════════

def get_hostname(ip: str) -> str:
    """DNS reverso con socket.gethostbyaddr."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def get_mac_from_arp(ip: str) -> Optional[str]:
    """Obtiene MAC via tabla ARP del SO. Scapy como ultimo recurso."""
    try:
        if IS_WINDOWS:
            r = subprocess.run(['arp', '-a', ip], capture_output=True, text=True,
                               encoding='utf-8', errors='replace', timeout=3,
                               creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            r = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=3)
        m = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', r.stdout)
        if m:
            return m.group(0).replace('-', ':').lower()
    except Exception:
        pass

    if not IS_WINDOWS:
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] != '00:00:00:00:00:00':
                            return parts[3].lower()
        except Exception:
            pass

    # Scapy ARP unicast como ultimo recurso
    if HAS_SCAPY:
        try:
            pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
            answered, _ = srp(pkt, timeout=2, verbose=False)
            if answered:
                return answered[0][1].hwsrc.lower()
        except Exception:
            pass

    return None


# ═══════════════════════════════════════════════════
# VENDOR OUI LOOKUP
# ═══════════════════════════════════════════════════

def get_vendor_from_mac(mac: str) -> str:
    """Identifica fabricante por OUI (primeros 3 bytes de la MAC)."""
    if not mac or mac in ('Unknown', ''):
        return 'Desconocido'
    mc = mac.replace(':', '').replace('-', '').upper()
    if len(mc) < 6:
        return 'Desconocido'
    oui = mc[:6]
    OUI = {
        'B827EB': 'Raspberry Pi', 'DCA632': 'Raspberry Pi', 'E45F01': 'Raspberry Pi',
        '005056': 'VMware', '000C29': 'VMware', '001C42': 'Parallels',
        '080027': 'VirtualBox', '00155D': 'Microsoft Hyper-V',
        'F81A67': 'TP-Link', '74DA38': 'TP-Link', 'A0F3C1': 'TP-Link',
        '50D4F7': 'TP-Link', 'B0487A': 'TP-Link',
        '98DAC4': 'D-Link', '00265A': 'D-Link',
        '001CF0': 'Cisco', '002545': 'Cisco', 'FCFBFB': 'Cisco',
        '000142': 'Cisco', 'E8BA70': 'Cisco',
        '28CDC1': 'Apple', 'A4C3F0': 'Apple', '3C15C2': 'Apple',
        '001B63': 'Apple', 'F0DBF8': 'Apple', 'ACDE48': 'Apple',
        'F431C3': 'Samsung', '0012FB': 'Samsung', '88329B': 'Samsung',
        '1864F6': 'Amazon', 'FC65DE': 'Amazon', '44650D': 'Amazon',
        'F0272D': 'Huawei', '4846FB': 'Huawei', 'ACCF85': 'Huawei',
        '0090F5': 'Ubiquiti', '24A43C': 'Ubiquiti', 'FCECDA': 'Ubiquiti',
        '44D9E7': 'Mikrotik', '488F5A': 'Mikrotik', '2CC81B': 'Mikrotik',
        '00E04C': 'Realtek', '525400': 'QEMU/KVM',
        '8086F2': 'Intel', 'A4C361': 'Intel', '001560': 'Intel',
        'B47C9C': 'Dell', '001A4B': 'Dell',
        '9CB6D0': 'HP', '3C4A92': 'HP', '001708': 'HP',
        'D8D385': 'Lenovo', '54EE75': 'Lenovo',
        '80FA5B': 'Xiaomi', '28E31F': 'Xiaomi',
        '80D2A5': 'ASUS', '10FEED': 'ASUS', '1CB72C': 'ASUS',
        '00D0C9': 'NETGEAR', 'A021B7': 'NETGEAR',
    }
    return OUI.get(oui, 'Desconocido')


# ═══════════════════════════════════════════════════
# TIPO DE DISPOSITIVO
# ═══════════════════════════════════════════════════

def detect_device_type(hostname: str, mac: str,
                       open_ports: list, os_info: str = '') -> str:
    """
    Clasifica el tipo de dispositivo usando:
    - os_info   : resultado de nmap -O
    - hostname  : nombre DNS del equipo
    - vendor    : fabricante por OUI de la MAC
    - open_ports: puertos TCP abiertos
    """
    h = hostname.lower()
    vendor = get_vendor_from_mac(mac).lower()
    os_l = os_info.lower()

    # Por SO detectado con nmap
    if any(x in os_l for x in ['router os', 'cisco ios', 'juniper']):
        return 'router'
    if 'android' in os_l:
        return 'phone'
    if 'windows server' in os_l:
        return 'server'
    if 'linux' in os_l and (22 in open_ports or 80 in open_ports):
        return 'server'
    if 'windows' in os_l:
        return 'desktop'
    if any(x in os_l for x in ['mac os', 'macos']):
        return 'laptop'

    # Por hostname
    if any(x in h for x in ['router', 'gateway', 'gw', 'rt-']):
        return 'router'
    if any(x in h for x in ['switch', 'sw-']):
        return 'switch'
    if any(x in h for x in ['ap-', 'wap', 'wifi', 'unifi', 'ubnt']):
        return 'wifi'
    if any(x in h for x in ['server', 'srv', 'nas', 'synology', 'qnap']):
        return 'server'
    if any(x in h for x in ['cam', 'camera', 'ipcam']):
        return 'camera'
    if any(x in h for x in ['phone', 'iphone', 'android', 'galaxy']):
        return 'phone'
    if any(x in h for x in ['tv', 'firetv', 'appletv', 'roku']):
        return 'tv'
    if any(x in h for x in ['print', 'hp-', 'canon-', 'epson-']):
        return 'printer'

    # Por vendor
    if any(x in vendor for x in ['raspberry', 'arduino']):
        return 'iot'
    if any(x in vendor for x in ['cisco', 'mikrotik', 'ubiquiti', 'netgear']):
        return 'router'
    if 'apple' in vendor:
        return 'laptop'
    if any(x in vendor for x in ['samsung', 'xiaomi']):
        return 'phone'
    if any(x in vendor for x in ['dell', 'hp', 'lenovo', 'asus']):
        return 'desktop'

    # Por puertos
    if 3389 in open_ports or 5900 in open_ports:
        return 'desktop'
    if 80 in open_ports or 443 in open_ports or 22 in open_ports:
        return 'server'

    return 'desktop'


# ═══════════════════════════════════════════════════
# TOPOLOGIA — traceroute + TTL
# ═══════════════════════════════════════════════════

import statistics as _stats_mod


def get_ttl(ip: str) -> int:
    """TTL de respuesta de ping para medir distancia."""
    try:
        if IS_WINDOWS:
            cmd = ['ping', '-n', '1', '-w', '1000', ip]
            extra = {'creationflags': subprocess.CREATE_NO_WINDOW}
        else:
            cmd = ['ping', '-c', '1', '-W', '1', ip]
            extra = {}
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=4, **extra)
        m = re.search(r'[Tt][Tt][Ll]=(\d+)', r.stdout)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return 0


def traceroute_to(ip: str, max_hops: int = 10, timeout: int = 2) -> list:
    """Detecta saltos intermedios hacia un destino."""
    hops = []
    try:
        if IS_WINDOWS:
            cmd = ['tracert', '-d', '-h', str(max_hops),
                   '-w', str(timeout * 1000), ip]
            extra = {'creationflags': subprocess.CREATE_NO_WINDOW}
        else:
            cmd = ['traceroute', '-n', '-m', str(max_hops),
                   '-w', str(timeout), '-q', '1', ip]
            extra = {}
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding='utf-8', errors='replace',
                           timeout=max_hops * timeout + 10, **extra)
        for line in r.stdout.splitlines():
            m = re.match(r'\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)', line)
            if m:
                rtt_m = re.search(r'([\d.]+)\s+ms', line)
                hops.append({'hop': int(m.group(1)), 'ip': m.group(2),
                             'rtt': float(rtt_m.group(1)) if rtt_m else None})
    except Exception:
        pass
    return hops


def detect_intermediary_devices(devices: list, gateway_ip: str, own_ip: str) -> dict:
    intermediaries = {}
    targets = [d for d in devices
               if d.get('ip') != own_ip and d.get('ip') != gateway_ip]
    for device in targets[:8]:
        ip = device.get('ip', '')
        if not ip:
            continue
        hops = traceroute_to(ip, max_hops=8, timeout=1)
        inter = [h for h in hops
                 if h['ip'] != gateway_ip
                 and h['ip'] != own_ip
                 and h['ip'] != ip]
        if inter:
            intermediaries[ip] = inter
    return intermediaries


def classify_topology(devices: list, gateway_ip: str,
                      own_ip: str, intermediaries: dict) -> dict:
    total = len(devices)
    if total == 0:
        return {'type': 'desconocida', 'confidence': 0,
                'description': 'Sin dispositivos detectados',
                'evidence': [], 'stats': {}}

    online = [d for d in devices if d.get('status') != 'offline']
    ttls = [t for t in (get_ttl(d.get('ip', '')) for d in online[:10]) if t > 0]
    dwi = len(intermediaries)
    all_inter = {h['ip'] for hops in intermediaries.values() for h in hops}
    rs = [d for d in devices if d.get('type') in ('router', 'switch', 'wifi')]
    ttl_var = (max(ttls) - min(ttls)) if len(ttls) >= 2 else 0

    if len(rs) >= 3 and dwi >= 2:
        t, c = 'malla', min(95, 60 + len(rs) * 10)
        desc = f"Red en malla: {len(rs)} equipos de red con {dwi} rutas intermedias."
    elif dwi >= 1 and len(all_inter) >= 1:
        t, c = 'arbol', min(90, 55 + dwi * 10)
        desc = f"Topologia en arbol: {len(all_inter)} switch(es) intermediario(s) detectados."
    elif len(online) <= 4 and ttl_var >= 10 and dwi >= 1:
        t, c = 'lineal', 65
        desc = f"Cadena lineal con variacion de TTL de {ttl_var}."
    elif dwi == 0 and ttl_var <= 5:
        t, c = 'estrella', min(95, 75 + (5 - ttl_var) * 4)
        desc = f"Estrella: {len(online)} dispositivos directamente al gateway ({gateway_ip})."
    elif len(rs) >= 2 or dwi >= 1:
        t, c = 'hibrida', 60
        desc = f"Topologia hibrida con {len(rs)} equipos de red."
    else:
        t, c = 'estrella', 70
        desc = f"{len(online)} dispositivos conectados al gateway sin intermediarios."

    evidence = [
        f"Dispositivos totales: {total} ({len(online)} en linea)",
        f"Gateway: {gateway_ip or '—'}",
        f"Rutas con intermediarios: {dwi}",
        f"Switches/routers intermediarios: {len(all_inter)}",
        f"Routers/switches en la red: {len(rs)}",
    ]
    if ttls:
        evidence.append(f"Rango TTL: {min(ttls)}–{max(ttls)} (variacion: {ttl_var})")

    return {
        'type': t, 'confidence': c, 'description': desc,
        'evidence': evidence, 'intermediaries': intermediaries,
        'stats': {'total_devices': total, 'online_devices': len(online),
                  'routers_switches': len(rs), 'intermediary_hops': dwi,
                  'unique_intermediaries': len(all_inter), 'ttl_variation': ttl_var}
    }


def build_smart_topology(devices: list, gateway_ip: str, own_ip: str) -> dict:
    intermediaries = detect_intermediary_devices(devices, gateway_ip, own_ip)
    topo_info = classify_topology(devices, gateway_ip, own_ip, intermediaries)
    nodes, edges, node_ids = [], [], {}

    nodes.append({'id': 'gateway', 'label': f'Gateway\n{gateway_ip or "Router"}',
                  'ip': gateway_ip or '', 'type': 'router', 'level': 0,
                  'vendor': '', 'status': 'online', 'mac': ''})
    if gateway_ip:
        node_ids[gateway_ip] = 'gateway'

    nodes.append({'id': 'server', 'label': f'AJFLUX\n{own_ip}',
                  'ip': own_ip, 'type': 'server', 'level': 1,
                  'vendor': '', 'status': 'online', 'mac': ''})
    node_ids[own_ip] = 'server'
    edges.append({'from': 'gateway', 'to': 'server'})

    all_inter_ips = {h['ip'] for hops in intermediaries.values() for h in hops}
    for i, inter_ip in enumerate(all_inter_ips):
        if inter_ip in node_ids:
            continue
        iid = f'inter_{i}'
        nodes.append({'id': iid, 'label': f'Switch\n{inter_ip}',
                      'ip': inter_ip, 'type': 'switch', 'level': 1,
                      'vendor': 'Intermediario', 'status': 'online', 'mac': ''})
        node_ids[inter_ip] = iid
        edges.append({'from': 'gateway', 'to': iid})

    for i, device in enumerate(devices):
        ip = device.get('ip', '')
        if not ip or ip == gateway_ip or ip == own_ip or ip in all_inter_ips:
            continue
        did = f'dev_{i}'
        node_ids[ip] = did
        nodes.append({'id': did,
                      'label': f"{device.get('hostname', ip)}\n{ip}",
                      'ip': ip, 'type': device.get('type', 'desktop'),
                      'level': 2 if ip in intermediaries else 1,
                      'mac': device.get('mac', ''),
                      'vendor': device.get('vendor', ''),
                      'status': device.get('status', 'online')})
        parent = 'gateway'
        if ip in intermediaries and intermediaries[ip]:
            parent = node_ids.get(intermediaries[ip][-1]['ip'], 'gateway')
        edges.append({'from': parent, 'to': did})

    return {'nodes': nodes, 'edges': edges, 'topology_info': topo_info}


def get_network_topology(devices: list, gateway_ip: str, own_ip: str) -> dict:
    """Alias de compatibilidad."""
    return build_smart_topology(devices, gateway_ip, own_ip)
