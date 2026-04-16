"""
Módulo de Sniffing de Red (Escucha de Tráfico)
Captura paquetes de la red utilizando la librería scapy.

Sniffing es una técnica de espionaje cibernético que consiste en la
intercepción y registro de datos que circulan por una red digital.

Los administradores de redes utilizan herramientas de sniffing para
diagnosticar problemas o monitorear el tráfico en la red digital.

Este módulo demuestra cómo:
- En puertos lógicos NO seguros, el atacante puede obtener TEXTO PLANO
  (texto claro) enviado por el usuario.
- En protocolos de comunicación seguros, la información circula ENCRIPTADA.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import threading
import os
import json


# Puertos/protocolos INSEGUROS: transmiten en texto plano
INSECURE_PORTS = {
    20: {'name': 'FTP-Data', 'risk': 'CRÍTICO', 'desc': 'Transferencia de archivos sin cifrar'},
    21: {'name': 'FTP', 'risk': 'CRÍTICO', 'desc': 'Credenciales y archivos en texto plano'},
    23: {'name': 'Telnet', 'risk': 'CRÍTICO', 'desc': 'Sesión remota completamente en texto plano'},
    25: {'name': 'SMTP', 'risk': 'ALTO', 'desc': 'Correos electrónicos sin cifrar'},
    53: {'name': 'DNS', 'risk': 'MEDIO', 'desc': 'Consultas DNS visibles (sitios visitados)'},
    80: {'name': 'HTTP', 'risk': 'ALTO', 'desc': 'Navegación web sin cifrar, contraseñas visibles'},
    110: {'name': 'POP3', 'risk': 'CRÍTICO', 'desc': 'Correo: usuario y contraseña en texto plano'},
    143: {'name': 'IMAP', 'risk': 'CRÍTICO', 'desc': 'Correo: credenciales en texto plano'},
    161: {'name': 'SNMP', 'risk': 'ALTO', 'desc': 'Monitoreo de red sin cifrar'},
    3306: {'name': 'MySQL', 'risk': 'CRÍTICO', 'desc': 'Base de datos: consultas y datos sin cifrar'},
    5432: {'name': 'PostgreSQL', 'risk': 'ALTO', 'desc': 'Base de datos sin cifrar por defecto'},
    6379: {'name': 'Redis', 'risk': 'CRÍTICO', 'desc': 'Base de datos en memoria sin autenticación'},
    8080: {'name': 'HTTP-Alt', 'risk': 'ALTO', 'desc': 'Servidor web alternativo sin cifrar'},
}

# Puertos/protocolos SEGUROS: transmiten datos encriptados
SECURE_PORTS = {
    22: {'name': 'SSH', 'desc': 'Conexión remota cifrada con SSH'},
    443: {'name': 'HTTPS', 'desc': 'Navegación web cifrada con TLS/SSL'},
    465: {'name': 'SMTPS', 'desc': 'Correo cifrado con SSL'},
    587: {'name': 'SMTP+TLS', 'desc': 'Correo con STARTTLS'},
    636: {'name': 'LDAPS', 'desc': 'Directorio cifrado con SSL'},
    853: {'name': 'DNS-TLS', 'desc': 'Consultas DNS cifradas'},
    993: {'name': 'IMAPS', 'desc': 'Correo IMAP cifrado con SSL'},
    995: {'name': 'POP3S', 'desc': 'Correo POP3 cifrado con SSL'},
    8443: {'name': 'HTTPS-Alt', 'desc': 'Servidor web alternativo cifrado'},
    3389: {'name': 'RDP', 'desc': 'Escritorio remoto (cifrado por defecto)'},
}


class NetworkSniffer:
    """
    Sniffer de red que captura, analiza y clasifica paquetes.
    Identifica si el tráfico usa protocolos seguros (cifrados) o
    inseguros (texto plano), demostrando riesgos de ciberseguridad.
    """
    
    def __init__(self):
        self.packets = []
        self.is_running = False
        self.capture_thread = None
        self.save_path = None
    
    def _process_packet(self, packet):
        """Procesa cada paquete capturado y extrae información relevante."""
        packet_info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'size': len(packet)
        }
        
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = 'Otro'
            
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                flags = packet[TCP].flags
                packet_info['flags'] = str(flags)
                
                # Clasificar seguridad del protocolo
                security = self._classify_security(packet[TCP].sport, packet[TCP].dport)
                packet_info.update(security)
                
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
                security = self._classify_security(packet[UDP].sport, packet[UDP].dport)
                packet_info.update(security)
                
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['src_port'] = '-'
                packet_info['dst_port'] = '-'
                packet_info['service'] = 'Ping/ICMP'
                packet_info['security'] = 'info'
                packet_info['security_label'] = 'Informativo'
                packet_info['risk'] = 'BAJO'
                packet_info['security_desc'] = 'Paquete de diagnóstico de red'
            else:
                packet_info['src_port'] = '-'
                packet_info['dst_port'] = '-'
                packet_info['service'] = 'Desconocido'
                packet_info['security'] = 'unknown'
                packet_info['security_label'] = 'Desconocido'
                packet_info['risk'] = '-'
                packet_info['security_desc'] = ''
            
            # Capturar datos del payload
            packet_info['data'] = ''
            packet_info['data_readable'] = False
            
            if Raw in packet:
                try:
                    raw_bytes = packet[Raw].load
                    raw_text = raw_bytes.decode('utf-8', errors='replace')[:200]
                    
                    # Verificar si el contenido es legible (texto plano)
                    printable_ratio = sum(1 for c in raw_text if c.isprintable() or c in '\r\n\t') / max(len(raw_text), 1)
                    
                    if printable_ratio > 0.7:
                        # ¡TEXTO PLANO DETECTADO! - Datos visibles para el atacante
                        packet_info['data'] = raw_text
                        packet_info['data_readable'] = True
                    else:
                        # Datos binarios/cifrados - no legibles
                        packet_info['data'] = f'[Datos cifrados/binarios - {len(raw_bytes)} bytes]'
                        packet_info['data_readable'] = False
                except Exception:
                    packet_info['data'] = '[Error al leer datos]'
                    packet_info['data_readable'] = False
            
            self.packets.append(packet_info)
    
    def _classify_security(self, src_port, dst_port):
        """
        Clasifica el tráfico como SEGURO o INSEGURO basado en el puerto.
        
        Puertos inseguros: transmiten en texto plano (FTP, HTTP, Telnet, etc.)
        Puertos seguros: transmiten datos cifrados (HTTPS, SSH, IMAPS, etc.)
        """
        # Verificar si usa un puerto inseguro
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
        
        # Verificar si usa un puerto seguro
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
        
        # Puerto desconocido
        return {
            'service': f'Puerto {min(src_port, dst_port)}',
            'security': 'unknown',
            'security_label': 'No clasificado',
            'risk': 'DESCONOCIDO',
            'security_desc': 'Protocolo no identificado'
        }
    
    def start_capture(self, count=50, filter_protocol='all', interface=None):
        """
        Inicia la captura de paquetes.
        
        Args:
            count: Número máximo de paquetes a capturar (máx 200)
            filter_protocol: Filtro de protocolo ('all', 'tcp', 'udp', 'icmp')
            interface: Interfaz de red (None = predeterminada)
        """
        if self.is_running:
            return {'success': False, 'error': 'Ya hay una captura en progreso.'}
        
        if count < 1:
            return {'success': False, 'error': 'La cantidad mínima de paquetes es 1.'}
        if count > 200:
            count = 200
        
        self.packets = []
        self.is_running = True
        
        # Construir filtro BPF
        bpf_filter = None
        if filter_protocol == 'tcp':
            bpf_filter = 'tcp'
        elif filter_protocol == 'udp':
            bpf_filter = 'udp'
        elif filter_protocol == 'icmp':
            bpf_filter = 'icmp'
        
        try:
            kwargs = {
                'prn': self._process_packet,
                'count': count,
                'store': False,
                'timeout': 30
            }
            if bpf_filter:
                kwargs['filter'] = bpf_filter
            if interface:
                kwargs['iface'] = interface
            
            sniff(**kwargs)
            
            self.is_running = False
            
            # Generar estadísticas de seguridad
            stats = self._generate_stats()
            
            return {
                'success': True,
                'packets': self.packets,
                'total_captured': len(self.packets),
                'filter': filter_protocol,
                'stats': stats
            }
            
        except PermissionError:
            self.is_running = False
            return {
                'success': False,
                'error': 'Se requieren permisos de administrador (root/sudo) para capturar tráfico de red.'
            }
        except Exception as e:
            self.is_running = False
            return {
                'success': False,
                'error': f'Error al capturar: {str(e)}'
            }
    
    def _generate_stats(self):
        """Genera estadísticas de seguridad de la captura."""
        total = len(self.packets)
        insecure = sum(1 for p in self.packets if p.get('security') == 'insecure')
        secure = sum(1 for p in self.packets if p.get('security') == 'secure')
        plaintext = sum(1 for p in self.packets if p.get('data_readable'))
        
        return {
            'total': total,
            'insecure': insecure,
            'secure': secure,
            'other': total - insecure - secure,
            'plaintext_detected': plaintext,
            'insecure_percent': round((insecure / max(total, 1)) * 100, 1),
            'secure_percent': round((secure / max(total, 1)) * 100, 1)
        }
    
    def save_capture(self, filepath, packets):
        """
        Guarda la captura en un archivo JSON.
        El archivo puede guardarse localmente o en una ruta remota.
        """
        try:
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            
            capture_data = {
                'capture_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_packets': len(packets),
                'description': 'Captura de tráfico de red - Análisis de protocolos seguros vs inseguros',
                'packets': packets
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(capture_data, f, indent=2, ensure_ascii=False)
            
            return {
                'success': True,
                'filepath': os.path.abspath(filepath),
                'total_saved': len(packets)
            }
        except PermissionError:
            return {
                'success': False,
                'error': f'Sin permisos para escribir en: {filepath}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error al guardar: {str(e)}'
            }


# Instancia global del sniffer
sniffer = NetworkSniffer()
