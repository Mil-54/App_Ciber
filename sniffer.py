"""
Módulo de Sniffer de Red
Captura tráfico de red con scapy y detecta transferencias de archivos HTTP.

NOTA EDUCATIVA: El sniffing de red permite ver el tráfico no cifrado.
Este módulo detecta automáticamente archivos transferidos por HTTP plano
(como el servidor Flask de la máquina atacada) y permite descargarlos.

Este módulo es EXCLUSIVAMENTE para fines educativos de Ciberseguridad.
"""

import os
import json
import base64
import threading
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


# ── Servicios conocidos ────────────────────────────────────────────────────────
KNOWN_SERVICES = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    110: 'POP3', 119: 'NNTP', 123: 'NTP', 135: 'RPC', 139: 'NetBIOS',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 194: 'IRC',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    514: 'Syslog', 587: 'SMTP-Submit', 636: 'LDAPS', 993: 'IMAPS',
    995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt',
    27017: 'MongoDB',
}

# Puertos considerados seguros (cifrados)
_SECURE_PORTS = {443, 993, 995, 465, 636, 8443, 22, 587}

# Puertos considerados inseguros (texto plano)
_INSECURE_PORTS = {80, 21, 23, 25, 110, 143, 8080, 5000, 8888, 20, 119, 3306, 5432}

# Niveles de riesgo por servicio
_RISK_MAP = {
    'HTTP':     'CRÍTICO',
    'HTTP-Alt': 'CRÍTICO',
    'FTP':      'CRÍTICO',
    'FTP-Data': 'CRÍTICO',
    'Telnet':   'CRÍTICO',
    'SMTP':     'ALTO',
    'POP3':     'ALTO',
    'IMAP':     'ALTO',
    'NetBIOS':  'ALTO',
    'SMB':      'ALTO',
    'SNMP':     'ALTO',
    'RDP':      'MEDIO',
    'MySQL':    'MEDIO',
    'PostgreSQL': 'MEDIO',
    'MongoDB':  'MEDIO',
    'MSSQL':    'MEDIO',
    'DNS':      'BAJO',
    'NTP':      'BAJO',
    'DHCP':     'BAJO',
    'SSH':      'NINGUNO',
    'HTTPS':    'NINGUNO',
    'IMAPS':    'NINGUNO',
    'POP3S':    'NINGUNO',
    'SMTPS':    'NINGUNO',
    'LDAPS':    'NINGUNO',
    'HTTPS-Alt':'NINGUNO',
    'ICMP':     'BAJO',
}


def _identify_service(port: int) -> str:
    return KNOWN_SERVICES.get(port, f'Puerto {port}')


def _get_security(port: int | None) -> str:
    """Clasifica el paquete como seguro, inseguro o info."""
    if port is None:
        return 'info'
    if port in _SECURE_PORTS:
        return 'secure'
    if port in _INSECURE_PORTS:
        return 'insecure'
    return 'info'


def _get_risk(service: str) -> str:
    return _RISK_MAP.get(service, 'BAJO')


# ── Reconstrucción de archivos HTTP ───────────────────────────────────────────

def _extract_http_file(payload: bytes) -> dict | None:
    """
    Intenta extraer un archivo de un payload HTTP multipart/form-data (upload)
    o de una respuesta HTTP con Content-Disposition: attachment (download).

    Retorna un dict con {filename, data_b64, direction, content_type} o None.
    """
    try:
        text = payload.decode('latin-1')  # latin-1 preserva bytes sin error
    except Exception:
        return None

    result = None

    # ── Caso 1: Upload (POST multipart/form-data) ────────────────────────────
    if b'Content-Disposition: form-data' in payload and b'filename="' in payload:
        import re
        match = re.search(r'filename="([^"]+)"', text)
        if not match:
            return None
        filename = match.group(1)

        boundary_match = re.search(r'boundary=([^\r\n ]+)', text)
        if not boundary_match:
            body_match = re.search(r'(--[^\r\n]+)\r\n', text)
            if not body_match:
                return None
            boundary = body_match.group(1)
        else:
            boundary = '--' + boundary_match.group(1).strip()

        parts = payload.split(boundary.encode('latin-1'))
        for part in parts:
            if b'filename="' in part:
                header_end = part.find(b'\r\n\r\n')
                if header_end == -1:
                    continue
                file_data = part[header_end + 4:]
                if file_data.endswith(b'\r\n'):
                    file_data = file_data[:-2]
                if len(file_data) > 0:
                    result = {
                        'filename': filename,
                        'data_b64': base64.b64encode(file_data).decode('utf-8'),
                        'size': len(file_data),
                        'direction': 'upload',
                        'content_type': _guess_content_type(filename),
                    }
                break

    # ── Caso 2: Download (GET response con Content-Disposition: attachment) ──
    elif b'Content-Disposition: attachment' in payload:
        import re
        match = re.search(r'filename="?([^\r\n"]+)"?', text)
        filename = match.group(1).strip() if match else 'archivo_descargado'

        header_end = payload.find(b'\r\n\r\n')
        if header_end != -1:
            file_data = payload[header_end + 4:]
            if len(file_data) > 0:
                result = {
                    'filename': filename,
                    'data_b64': base64.b64encode(file_data).decode('utf-8'),
                    'size': len(file_data),
                    'direction': 'download',
                    'content_type': _guess_content_type(filename),
                }

    return result


def _guess_content_type(filename: str) -> str:
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    types = {
        'pdf': 'application/pdf', 'png': 'image/png', 'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg', 'gif': 'image/gif', 'txt': 'text/plain',
        'zip': 'application/zip', 'py': 'text/x-python', 'js': 'text/javascript',
        'html': 'text/html', 'css': 'text/css', 'json': 'application/json',
        'xml': 'application/xml', 'csv': 'text/csv',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    }
    return types.get(ext, 'application/octet-stream')


def _extract_payload_preview(raw: bytes, max_len: int = 200) -> tuple[str, bool]:
    """
    Devuelve (preview_texto, es_texto_legible).
    Si hay HTTP plano, extrae la primera línea o fragmento visible.
    """
    try:
        decoded = raw[:max_len].decode('utf-8', errors='replace')
    except Exception:
        return repr(raw[:max_len]), False

    # ¿Parece HTTP?
    if decoded.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'HTTP/')):
        # Tomar la primera línea + headers relevantes
        first_part = decoded.split('\r\n\r\n')[0][:max_len]
        return first_part.replace('\r\n', ' | '), True

    # ¿Es texto ASCII imprimible en su mayoría?
    printable = sum(1 for c in decoded if c.isprintable() or c in '\r\n\t')
    if printable / max(len(decoded), 1) > 0.7:
        return decoded.strip()[:max_len], True

    return '(datos binarios)', False


# ── Clase principal ────────────────────────────────────────────────────────────

class NetworkSniffer:
    """
    Sniffer de red educativo.
    Captura paquetes, guarda la captura y reconstruye archivos
    transferidos por HTTP plano (sin cifrar).
    """

    def __init__(self):
        self.captured_packets: list = []
        self.intercepted_files: list = []
        self._lock = threading.Lock()

        # Modo remoto
        self._remote_packets: list = []
        self._remote_files: list = []
        self._remote_lock = threading.Lock()
        self._remote_agent_info: dict = {}
        self._remote_complete: bool = False

    # ── Captura local ─────────────────────────────────────────────────────────

    def start_capture(self, count: int = 50, filter_protocol: str = 'all',
                      interface: str = None) -> dict:
        """Inicia la captura de paquetes en la interfaz local."""
        if not _SCAPY_AVAILABLE:
            return {'success': False, 'error': 'scapy no está instalado.'}

        self.captured_packets = []
        self.intercepted_files = []

        filter_map = {
            'tcp': 'tcp', 'udp': 'udp', 'icmp': 'icmp', 'all': None
        }
        bpf = filter_map.get(filter_protocol)

        try:
            kwargs = {'count': count, 'store': True}
            if bpf:
                kwargs['filter'] = bpf
            if interface:
                kwargs['iface'] = interface

            packets = sniff(**kwargs)

            for pkt in packets:
                parsed = self._parse_packet(pkt)
                if parsed:
                    self.captured_packets.append(parsed)

            # Calcular estadísticas
            stats = self._compute_stats(self.captured_packets)

            return {
                'success': True,
                'packets': self.captured_packets,
                'total': len(self.captured_packets),
                'total_captured': len(self.captured_packets),
                'filter': filter_protocol,
                'stats': stats,
                'intercepted_files': self.intercepted_files,
                'total_files': len(self.intercepted_files),
            }

        except PermissionError:
            return {'success': False, 'error': 'Se requieren permisos de administrador (sudo).'}
        except Exception as e:
            return {'success': False, 'error': f'Error en la captura: {str(e)}'}

    def _compute_stats(self, packets: list) -> dict:
        """Calcula el resumen de seguridad para el dashboard."""
        insecure = sum(1 for p in packets if p.get('security') == 'insecure')
        secure   = sum(1 for p in packets if p.get('security') == 'secure')
        plaintext = sum(1 for p in packets if p.get('data_readable'))
        return {
            'insecure':          insecure,
            'secure':            secure,
            'total':             len(packets),
            'plaintext_detected': plaintext,
        }

    def _parse_packet(self, pkt) -> dict | None:
        """Extrae información relevante de un paquete scapy."""
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'protocol': 'OTHER',
            'src_port': None,
            'dst_port': None,
            'service': 'Desconocido',
            'size': len(pkt),
            'payload_preview': '',
            # Campos para el frontend
            'security': 'info',
            'risk': 'BAJO',
            'data': '',
            'data_readable': False,
        }

        effective_port = None  # puerto "relevante" para determinar seguridad

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info['protocol'] = 'TCP'
            info['src_port'] = tcp.sport
            info['dst_port'] = tcp.dport
            # El puerto destino suele indicar el servicio
            srv_dst = _identify_service(tcp.dport)
            srv_src = _identify_service(tcp.sport)
            info['service'] = srv_dst if not srv_dst.startswith('Puerto') else srv_src
            effective_port = tcp.dport

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info['protocol'] = 'UDP'
            info['src_port'] = udp.sport
            info['dst_port'] = udp.dport
            srv_dst = _identify_service(udp.dport)
            srv_src = _identify_service(udp.sport)
            info['service'] = srv_dst if not srv_dst.startswith('Puerto') else srv_src
            effective_port = udp.dport

        elif pkt.haslayer(ICMP):
            info['protocol'] = 'ICMP'
            info['service'] = 'ICMP'

        # Seguridad y riesgo
        info['security'] = _get_security(effective_port)
        # Si src_port también es conocido e inseguro, prevalece insegure
        if info['security'] == 'info' and info.get('src_port'):
            info['security'] = _get_security(info['src_port'])
        info['risk'] = _get_risk(info['service'])

        # Payload
        if pkt.haslayer(Raw):
            raw: bytes = pkt[Raw].load
            preview, readable = _extract_payload_preview(raw)
            info['payload_preview'] = preview
            info['data'] = preview
            info['data_readable'] = readable

            # Intentar extraer archivo HTTP
            http_ports = (80, 8080, 5000, 8888)
            if (info['service'] in ('HTTP', 'HTTP-Alt') or
                    info.get('dst_port') in http_ports or
                    info.get('src_port') in http_ports):
                file_info = _extract_http_file(raw)
                if file_info:
                    file_info['timestamp'] = info['timestamp']
                    file_info['src_ip'] = info['src_ip']
                    file_info['dst_ip'] = info['dst_ip']
                    with self._lock:
                        self.intercepted_files.append(file_info)

        return info

    # ── Guardar captura en disco ───────────────────────────────────────────────

    def save_capture(self, filepath: str, packets: list) -> dict:
        """
        Guarda los paquetes capturados en un archivo JSON en el servidor.
        """
        try:
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)

            clean_packets = [
                {k: v for k, v in p.items() if k != 'data_b64'}
                for p in packets
            ]

            log_data = {
                'capture_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_packets': len(clean_packets),
                'warning': 'Este archivo es solo para fines educativos de Ciberseguridad.',
                'packets': clean_packets,
            }

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False)

            return {
                'success': True,
                'filepath': os.path.abspath(filepath),
                'total_saved': len(clean_packets),
            }

        except PermissionError:
            return {'success': False, 'error': f'Sin permisos para escribir en: {filepath}'}
        except Exception as e:
            return {'success': False, 'error': f'Error al guardar: {str(e)}'}

    def get_capture_json(self, packets: list) -> str:
        """Genera el JSON de captura en memoria (para descarga desde el navegador)."""
        clean_packets = [
            {k: v for k, v in p.items() if k != 'data_b64'}
            for p in packets
        ]
        log_data = {
            'capture_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_packets': len(clean_packets),
            'warning': 'Este archivo es solo para fines educativos de Ciberseguridad.',
            'packets': clean_packets,
        }
        return json.dumps(log_data, indent=2, ensure_ascii=False)

    def save_intercepted_file(self, file_index: int, dest_folder: str = 'intercepted_files') -> dict:
        """
        Guarda en disco un archivo interceptado (por índice) y retorna la ruta.
        """
        try:
            all_files = self.intercepted_files + self._remote_files
            if file_index < 0 or file_index >= len(all_files):
                return {'success': False, 'error': 'Índice de archivo fuera de rango.'}

            file_info = all_files[file_index]
            os.makedirs(dest_folder, exist_ok=True)
            dest_path = os.path.join(dest_folder, file_info['filename'])

            file_bytes = base64.b64decode(file_info['data_b64'])
            with open(dest_path, 'wb') as f:
                f.write(file_bytes)

            return {
                'success': True,
                'filepath': os.path.abspath(dest_path),
                'filename': file_info['filename'],
                'size': len(file_bytes),
            }
        except Exception as e:
            return {'success': False, 'error': f'Error al guardar archivo: {str(e)}'}

    def get_intercepted_file_bytes(self, file_index: int) -> bytes | None:
        """Retorna los bytes de un archivo interceptado para enviarlo como descarga."""
        all_files = self.intercepted_files + self._remote_files
        if 0 <= file_index < len(all_files):
            try:
                return base64.b64decode(all_files[file_index]['data_b64'])
            except Exception:
                return None
        return None

    def get_intercepted_file_info(self, file_index: int) -> dict | None:
        """Retorna la metadata de un archivo interceptado."""
        all_files = self.intercepted_files + self._remote_files
        if 0 <= file_index < len(all_files):
            return all_files[file_index]
        return None

    # ── Modo Remoto ───────────────────────────────────────────────────────────

    def register_remote_agent(self, agent_info: dict) -> dict:
        with self._remote_lock:
            self._remote_packets = []
            self._remote_files = []
            self._remote_complete = False
            self._remote_agent_info = agent_info
        return {'success': True, 'message': f"Agente {agent_info.get('agent_ip')} registrado en modo sniffer."}

    def receive_remote_packets(self, packets: list, final: bool = False) -> dict:
        """Recibe paquetes desde remote_agent.py y extrae archivos HTTP si los hay."""
        new_files = []
        for p in packets:
            raw_b64 = p.pop('payload_raw_b64', None)
            if raw_b64:
                try:
                    raw = base64.b64decode(raw_b64)
                    file_info = _extract_http_file(raw)
                    if file_info:
                        file_info['timestamp'] = p.get('timestamp', '')
                        file_info['src_ip'] = p.get('src_ip', '')
                        file_info['dst_ip'] = p.get('dst_ip', '')
                        new_files.append(file_info)
                except Exception:
                    pass

            # Asegurar campos de seguridad en paquetes remotos
            if 'security' not in p:
                port = p.get('dst_port')
                p['security'] = _get_security(port)
                p['risk'] = _get_risk(p.get('service', ''))

        with self._remote_lock:
            self._remote_packets.extend(packets)
            self._remote_files.extend(new_files)
            if final:
                self._remote_complete = True

        return {
            'success': True,
            'received': len(packets),
            'files_extracted': len(new_files),
        }

    def get_remote_results(self) -> dict:
        with self._remote_lock:
            packets = list(self._remote_packets)
            files = list(self._remote_files)
            complete = self._remote_complete
            agent = dict(self._remote_agent_info)

        files_meta = [
            {k: v for k, v in f.items() if k != 'data_b64'}
            for f in files
        ]

        stats = self._compute_stats(packets)

        return {
            'success': True,
            'packets': packets,
            'total': len(packets),
            'total_captured': len(packets),
            'filter': agent.get('filter', 'all'),
            'complete': complete,
            'agent': agent,
            'stats': stats,
            'intercepted_files': files_meta,
            'total_files': len(files_meta),
        }


# Instancia global
sniffer = NetworkSniffer()