"""
Módulo de Sniffing de Red (Escucha de Tráfico)
Captura paquetes de la red utilizando la librería scapy.
Los administradores de redes utilizan herramientas de sniffing para
diagnosticar problemas o monitorear el tráfico en la red digital.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import threading
import os
import json


class NetworkSniffer:
    """Sniffer de red que captura y almacena paquetes."""
    
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
                # Identificar servicio conocido
                packet_info['service'] = self._identify_service(packet[TCP].sport, packet[TCP].dport)
                # Flags TCP
                flags = packet[TCP].flags
                packet_info['flags'] = str(flags)
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                packet_info['service'] = self._identify_service(packet[UDP].sport, packet[UDP].dport)
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['src_port'] = '-'
                packet_info['dst_port'] = '-'
                packet_info['service'] = 'Ping/ICMP'
            else:
                packet_info['src_port'] = '-'
                packet_info['dst_port'] = '-'
                packet_info['service'] = 'Desconocido'
            
            # Capturar datos del payload (primeros 100 chars)
            if Raw in packet:
                try:
                    raw_data = packet[Raw].load.decode('utf-8', errors='replace')[:100]
                    packet_info['data'] = raw_data
                except Exception:
                    packet_info['data'] = '[datos binarios]'
            else:
                packet_info['data'] = ''
            
            self.packets.append(packet_info)
    
    def _identify_service(self, src_port, dst_port):
        """Identifica el servicio basado en el puerto."""
        known_ports = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        
        if dst_port in known_ports:
            return known_ports[dst_port]
        if src_port in known_ports:
            return known_ports[src_port]
        return f'Puerto {min(src_port, dst_port)}'
    
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
            
            return {
                'success': True,
                'packets': self.packets,
                'total_captured': len(self.packets),
                'filter': filter_protocol
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
    
    def save_capture(self, filepath, packets):
        """
        Guarda la captura en un archivo JSON.
        El archivo puede guardarse localmente o en una ruta remota.
        
        Args:
            filepath: Ruta del archivo donde guardar
            packets: Lista de paquetes capturados
        """
        try:
            # Crear directorio si no existe
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            
            capture_data = {
                'capture_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_packets': len(packets),
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
