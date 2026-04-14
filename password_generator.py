"""
Módulo Generador de Contraseñas Seguras
Genera contraseñas combinando letras (mayúsculas/minúsculas), números y caracteres especiales.
"""

import string
import secrets


def generate_passwords(length: int, count: int) -> dict:
    """
    Genera contraseñas seguras de la longitud y cantidad indicadas.
    
    Args:
        length: Longitud de cada contraseña (mínimo 8 caracteres)
        count: Cantidad de contraseñas a generar (mínimo 1, máximo 100)
    
    Returns:
        dict con las contraseñas generadas o un mensaje de error
    """
    # Validación de longitud mínima
    if length < 8:
        return {
            'success': False,
            'error': 'La longitud mínima de la contraseña es de 8 caracteres.'
        }
    
    # Validación de cantidad
    if count < 1:
        return {
            'success': False,
            'error': 'La cantidad mínima de contraseñas es 1.'
        }
    
    if count > 100:
        return {
            'success': False,
            'error': 'La cantidad máxima de contraseñas es 100.'
        }

    # Conjuntos de caracteres
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:',.<>?/"
    
    all_chars = lowercase + uppercase + digits + special
    
    passwords = []
    for _ in range(count):
        password = _generate_single_password(length, lowercase, uppercase, digits, special, all_chars)
        
        # Análisis de fortaleza
        strength = _evaluate_strength(password)
        
        passwords.append({
            'password': password,
            'length': len(password),
            'strength': strength
        })
    
    return {
        'success': True,
        'passwords': passwords,
        'count': count,
        'length': length
    }


def _generate_single_password(length, lowercase, uppercase, digits, special, all_chars):
    """Genera una contraseña que garantiza al menos 1 carácter de cada tipo."""
    while True:
        # Garantizar al menos un carácter de cada tipo
        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Rellenar el resto con caracteres aleatorios del conjunto completo
        for _ in range(length - 4):
            password_chars.append(secrets.choice(all_chars))
        
        # Mezclar los caracteres de forma segura
        secrets.SystemRandom().shuffle(password_chars)
        password = ''.join(password_chars)
        
        # Verificar que cumple con los requisitos
        if (_has_lowercase(password) and _has_uppercase(password) and
                _has_digit(password) and _has_special(password)):
            return password


def _has_lowercase(password):
    return any(c in string.ascii_lowercase for c in password)


def _has_uppercase(password):
    return any(c in string.ascii_uppercase for c in password)


def _has_digit(password):
    return any(c in string.digits for c in password)


def _has_special(password):
    special = set("!@#$%^&*()-_=+[]{}|;:',.<>?/")
    return any(c in special for c in password)


def _evaluate_strength(password):
    """Evalúa la fortaleza de una contraseña."""
    score = 0
    
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    if _has_lowercase(password):
        score += 1
    if _has_uppercase(password):
        score += 1
    if _has_digit(password):
        score += 1
    if _has_special(password):
        score += 1
    
    # Verificar variedad de caracteres
    unique_ratio = len(set(password)) / len(password)
    if unique_ratio > 0.7:
        score += 1
    
    if score >= 7:
        return 'Muy Fuerte'
    elif score >= 5:
        return 'Fuerte'
    elif score >= 3:
        return 'Media'
    else:
        return 'Débil'
