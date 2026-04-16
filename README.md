# 🛡️ CyberTool — Aplicación de Hacking Ético

Aplicación web desarrollada en **Python** con **Flask** para la materia de **Ciberseguridad**. Incluye tres módulos principales de hacking ético:

1. **📡 Escáner de Puertos Lógicos** — Usando la librería `python-nmap`
2. **🔑 Generador de Contraseñas Seguras** — Con validación y evaluación de fortaleza
3. **🕵️ Sniffer de Red** — Captura y análisis de tráfico de red con `scapy`

---

## 📋 Descripción de los Módulos

### 1. Escáner de Puertos Lógicos (`scanner.py`)

Utiliza la librería `python-nmap` (wrapper de la herramienta nmap del sistema) para escanear puertos lógicos abiertos de un equipo remoto.

**Modos de escaneo disponibles:**

| Modo | Descripción |
|------|-------------|
| 🎯 Puerto específico | Escanea un puerto lógico en particular (ej: puerto 80) |
| 📊 Rango de puertos | Escanea un rango definido por el usuario (ej: 1-1024) |
| 🌐 Todos los puertos | Escanea la totalidad de puertos (1-65535) mostrando solo los abiertos |

**Información mostrada por cada puerto:**
- Número de puerto
- Estado (abierto/cerrado/filtrado)
- Servicio asociado (HTTP, SSH, FTP, etc.)
- Protocolo (TCP/UDP)

### 2. Generador de Contraseñas Seguras (`password_generator.py`)

Genera contraseñas seguras de la longitud y cantidad que el usuario indique.

**Características:**
- El usuario indica la **longitud** de la contraseña
- El usuario indica la **cantidad** de contraseñas a generar
- **Validación:** longitud mínima de 8 caracteres
- Cada contraseña combina:
  - ✅ Letras mayúsculas (A-Z)
  - ✅ Letras minúsculas (a-z)
  - ✅ Números (0-9)
  - ✅ Caracteres especiales (!@#$%^&*...)
- Se garantiza al menos 1 carácter de cada tipo en cada contraseña
- Evaluación de fortaleza: Muy Fuerte, Fuerte, Media, Débil
- Usa el módulo `secrets` de Python para generación criptográficamente segura

### 3. Sniffer de Red (`sniffer.py`)

Los administradores de redes utilizan herramientas de sniffing para diagnosticar problemas o monitorear el tráfico en la red digital. Este módulo captura paquetes de red en tiempo real usando la librería `scapy`.

**Características:**
- Captura de paquetes en tiempo real con cantidad configurable (máx. 200)
- Filtros por protocolo: **TCP**, **UDP**, **ICMP** o todos
- Selección de interfaz de red (eth0, wlan0, etc.)
- Identificación automática de servicios (HTTP, SSH, DNS, MySQL, etc.)
- Extracción de datos del payload
- **Guardar captura en archivo JSON** — el archivo se puede guardar en el equipo local o en una ruta remota

**Información mostrada por cada paquete:**
- Timestamp (hora de captura)
- Protocolo (TCP/UDP/ICMP)
- IP y puerto de origen
- IP y puerto de destino
- Servicio identificado
- Tamaño del paquete

> ⚠️ Se requieren permisos de administrador (sudo) para capturar tráfico de red.

---

## 🗂️ Estructura del Proyecto

```
APP/
├── app.py                  # Servidor Flask principal (rutas y endpoints)
├── scanner.py              # Módulo de escaneo de puertos con python-nmap
├── password_generator.py   # Módulo generador de contraseñas seguras
├── sniffer.py              # Módulo de sniffing de red con scapy
├── requirements.txt        # Dependencias de Python
├── templates/
│   └── index.html          # Interfaz web principal
└── static/
    ├── style.css           # Estilos (tema oscuro estilo terminal)
    └── script.js           # Lógica del frontend (AJAX, validación)
```

---

## 🛠️ Tecnologías Utilizadas

| Tecnología | Uso |
|------------|-----|
| **Python 3** | Lenguaje de programación principal |
| **Flask** | Framework web para el servidor backend |
| **python-nmap** | Wrapper de nmap para escaneo de puertos |
| **nmap** | Herramienta del sistema para escaneo de red |
| **scapy** | Librería para captura y análisis de paquetes de red |
| **HTML/CSS/JS** | Frontend con diseño dark mode |
| **secrets** | Módulo de Python para generación segura de contraseñas |

---

## ⚙️ Requisitos Previos

- **Python 3.8+**
- **nmap** instalado en el sistema operativo
- **pip** para instalar dependencias

---

## 🚀 Instalación y Ejecución

### Paso 1: Instalar nmap en el sistema

```bash
# Arch Linux / Manjaro
sudo pacman -S nmap

# Ubuntu / Debian
sudo apt install nmap

# Fedora
sudo dnf install nmap
```

### Paso 2: Clonar el repositorio

```bash
git clone https://github.com/Mil-54/App_Ciber.git
cd App_Ciber
```

### Paso 3: Crear entorno virtual (recomendado)

```bash
python -m venv .venv
source .venv/bin/activate
```

### Paso 4: Instalar dependencias de Python

```bash
pip install -r requirements.txt
```

### Paso 5: Ejecutar la aplicación

```bash
# Ejecución normal (escáner de puertos y generador de contraseñas)
python app.py

# Con permisos de root (necesario para el sniffer de red)
sudo python app.py
```

### Paso 6: Abrir en el navegador

```
http://127.0.0.1:5000
```

---

## 📡 API Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/` | Página principal (interfaz web) |
| POST | `/scan` | Escaneo de puertos lógicos |
| POST | `/generate-passwords` | Generación de contraseñas seguras |
| POST | `/sniff` | Captura de tráfico de red (sniffing) |
| POST | `/save-capture` | Guardar captura en archivo JSON |

### Ejemplo de uso — Escaneo de puertos

```json
POST /scan
{
    "host": "192.168.1.1",
    "scan_type": "single",
    "port": 80
}
```

**Tipos de escaneo:** `single` (puerto específico), `range` (rango), `all` (todos)

### Ejemplo de uso — Generador de contraseñas

```json
POST /generate-passwords
{
    "length": 16,
    "count": 5
}
```

### Ejemplo de uso — Sniffer de red

```json
POST /sniff
{
    "count": 50,
    "filter": "tcp",
    "interface": "eth0"
}
```

**Filtros disponibles:** `all` (todos), `tcp`, `udp`, `icmp`

### Ejemplo de uso — Guardar captura

```json
POST /save-capture
{
    "filepath": "/home/usuario/captura.json",
    "packets": [ ... ]
}
```

El archivo se puede guardar en el equipo local o en una ruta de red montada.

---

## ⚠️ Aviso Legal

> Esta herramienta es **exclusivamente para fines educativos** en el marco de la materia de Ciberseguridad. El escaneo de puertos y la captura de tráfico de red en equipos sin autorización explícita es **ilegal**. Úsala solo en equipos propios o con permiso del propietario.

---

## 👨‍💻 Información Académica

- **Materia:** Ciberseguridad
- **Grupo:** 3801
- **Año:** 2026
- **Lenguaje:** Python
- **Librerías principales:** Flask, python-nmap, scapy, secrets
