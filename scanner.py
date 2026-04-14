"""
Módulo de Escaneo de Puertos Lógicos
Utiliza python-nmap como wrapper de la herramienta nmap del sistema.
"""

import nmap


def scan_single_port(host: str, port: int) -> dict:
    """Escanea un puerto lógico específico de un host remoto."""
    nm = nmap.PortScanner()
    try:
        nm.scan(host, str(port), arguments='-T4')
        results = []
        for scanned_host in nm.all_hosts():
            for proto in nm[scanned_host].all_protocols():
                if port in nm[scanned_host][proto]:
                    port_info = nm[scanned_host][proto][port]
                    results.append({
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'desconocido'),
                        'protocol': proto
                    })
        return {
            'success': True,
            'host': host,
            'scan_type': 'Puerto específico',
            'results': results,
            'total_open': sum(1 for r in results if r['state'] == 'open')
        }
    except nmap.PortScannerError as e:
        return {'success': False, 'error': f'Error de nmap: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Error: {str(e)}'}


def scan_port_range(host: str, start_port: int, end_port: int) -> dict:
    """Escanea un rango de puertos lógicos y muestra solo los abiertos."""
    nm = nmap.PortScanner()
    try:
        port_range = f'{start_port}-{end_port}'
        nm.scan(host, port_range, arguments='-T4')
        results = []
        for scanned_host in nm.all_hosts():
            for proto in nm[scanned_host].all_protocols():
                ports = sorted(nm[scanned_host][proto].keys())
                for port in ports:
                    port_info = nm[scanned_host][proto][port]
                    if port_info['state'] == 'open':
                        results.append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'desconocido'),
                            'protocol': proto
                        })
        return {
            'success': True,
            'host': host,
            'scan_type': f'Rango {start_port}-{end_port}',
            'results': results,
            'total_open': len(results)
        }
    except nmap.PortScannerError as e:
        return {'success': False, 'error': f'Error de nmap: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Error: {str(e)}'}


def scan_all_ports(host: str) -> dict:
    """Escanea todos los puertos lógicos (1-65535) y muestra solo los abiertos."""
    nm = nmap.PortScanner()
    try:
        nm.scan(host, '1-65535', arguments='-T4 --open')
        results = []
        for scanned_host in nm.all_hosts():
            for proto in nm[scanned_host].all_protocols():
                ports = sorted(nm[scanned_host][proto].keys())
                for port in ports:
                    port_info = nm[scanned_host][proto][port]
                    if port_info['state'] == 'open':
                        results.append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'desconocido'),
                            'protocol': proto
                        })
        return {
            'success': True,
            'host': host,
            'scan_type': 'Todos los puertos (1-65535)',
            'results': results,
            'total_open': len(results)
        }
    except nmap.PortScannerError as e:
        return {'success': False, 'error': f'Error de nmap: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Error: {str(e)}'}
