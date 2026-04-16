"""
Aplicación de Hacking Ético - Ciberseguridad
Servidor Flask principal con endpoints para escaneo de puertos, generación de contraseñas y sniffing de red.
"""

from flask import Flask, render_template, request, jsonify
from scanner import scan_single_port, scan_port_range, scan_all_ports
from password_generator import generate_passwords
from sniffer import sniffer

app = Flask(__name__)


@app.route('/')
def index():
    """Página principal de la aplicación."""
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    """Endpoint para escaneo de puertos lógicos."""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No se recibieron datos.'}), 400
    
    host = data.get('host', '').strip()
    scan_type = data.get('scan_type', '')
    
    if not host:
        return jsonify({'success': False, 'error': 'Debe indicar una dirección IP o hostname.'}), 400
    
    try:
        if scan_type == 'single':
            port = data.get('port')
            if not port:
                return jsonify({'success': False, 'error': 'Debe indicar un número de puerto.'}), 400
            port = int(port)
            if port < 1 or port > 65535:
                return jsonify({'success': False, 'error': 'El puerto debe estar entre 1 y 65535.'}), 400
            result = scan_single_port(host, port)
            
        elif scan_type == 'range':
            start_port = data.get('start_port')
            end_port = data.get('end_port')
            if not start_port or not end_port:
                return jsonify({'success': False, 'error': 'Debe indicar el rango de puertos.'}), 400
            start_port = int(start_port)
            end_port = int(end_port)
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                return jsonify({'success': False, 'error': 'Rango de puertos inválido (1-65535).'}), 400
            result = scan_port_range(host, start_port, end_port)
            
        elif scan_type == 'all':
            result = scan_all_ports(host)
            
        else:
            return jsonify({'success': False, 'error': 'Tipo de escaneo no válido.'}), 400
        
        return jsonify(result)
        
    except ValueError:
        return jsonify({'success': False, 'error': 'Los puertos deben ser números enteros.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error inesperado: {str(e)}'}), 500


@app.route('/generate-passwords', methods=['POST'])
def gen_passwords():
    """Endpoint para generación de contraseñas seguras."""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No se recibieron datos.'}), 400
    
    try:
        length = int(data.get('length', 0))
        count = int(data.get('count', 0))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'La longitud y cantidad deben ser números enteros.'}), 400
    
    result = generate_passwords(length, count)
    return jsonify(result)


@app.route('/sniff', methods=['POST'])
def sniff_network():
    """Endpoint para captura de tráfico de red (sniffing)."""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No se recibieron datos.'}), 400
    
    try:
        count = int(data.get('count', 50))
        filter_protocol = data.get('filter', 'all')
        interface = data.get('interface', None)
        
        if filter_protocol not in ['all', 'tcp', 'udp', 'icmp']:
            return jsonify({'success': False, 'error': 'Filtro no válido. Use: all, tcp, udp, icmp'}), 400
        
        result = sniffer.start_capture(
            count=count,
            filter_protocol=filter_protocol,
            interface=interface if interface else None
        )
        return jsonify(result)
        
    except ValueError:
        return jsonify({'success': False, 'error': 'La cantidad debe ser un número entero.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error inesperado: {str(e)}'}), 500


@app.route('/save-capture', methods=['POST'])
def save_capture():
    """Endpoint para guardar la captura en un archivo."""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No se recibieron datos.'}), 400
    
    filepath = data.get('filepath', '').strip()
    packets = data.get('packets', [])
    
    if not filepath:
        return jsonify({'success': False, 'error': 'Debe indicar la ruta del archivo.'}), 400
    
    if not packets:
        return jsonify({'success': False, 'error': 'No hay paquetes para guardar.'}), 400
    
    # Agregar extensión .json si no la tiene
    if not filepath.endswith('.json'):
        filepath += '.json'
    
    result = sniffer.save_capture(filepath, packets)
    return jsonify(result)


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  🔒 Aplicación de Hacking Ético - Ciberseguridad")
    print("  📡 Escáner de Puertos | 🔑 Contraseñas | 🕵️ Sniffer")
    print("=" * 60)
    print("  Servidor corriendo en: http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
