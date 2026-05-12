"""
arch.py — Servidor de archivos para la MÁQUINA VÍCTIMA del laboratorio.

La víctima ejecuta este script. El atacante puede conectarse desde su
CyberTool, escribir la IP de la víctima, y ver / descargar los archivos.

Ejecutar en la máquina víctima:
    python arch.py

Acceder desde el navegador de la víctima: http://localhost:5001
El atacante accede desde su CyberTool → tab "Servidor de Archivos" → IP de la víctima
"""

import os
from datetime import datetime
from flask import Flask, request, redirect, url_for, send_from_directory, jsonify
from flask import render_template_string

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# ── Helpers ───────────────────────────────────────────────────────────────────

def _file_size_str(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


def _file_icon(name: str) -> str:
    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    icons = {
        'pdf': '📄', 'png': '🖼️', 'jpg': '🖼️', 'jpeg': '🖼️', 'gif': '🖼️',
        'txt': '📝', 'py': '🐍', 'js': '⚡', 'html': '🌐', 'css': '🎨',
        'json': '📦', 'xml': '📋', 'csv': '📊', 'zip': '🗜️',
        'docx': '📝', 'xlsx': '📊', 'mp4': '🎥', 'mp3': '🎵',
        'exe': '⚙️', 'sh': '💻', 'bat': '💻',
    }
    return icons.get(ext, '📁')


def _guess_mime(name: str) -> str:
    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    types = {
        'pdf': 'application/pdf', 'png': 'image/png', 'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg', 'gif': 'image/gif', 'txt': 'text/plain',
        'zip': 'application/zip', 'py': 'text/x-python', 'js': 'text/javascript',
        'html': 'text/html', 'css': 'text/css', 'json': 'application/json',
        'xml': 'application/xml', 'csv': 'text/csv',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'mp4': 'video/mp4', 'mp3': 'audio/mpeg',
        'exe': 'application/octet-stream', 'sh': 'text/x-shellscript',
    }
    return types.get(ext, 'application/octet-stream')


def _list_files() -> list:
    """Lista todos los archivos en la carpeta de subida."""
    files = []
    for name in os.listdir(UPLOAD_FOLDER):
        path = os.path.join(UPLOAD_FOLDER, name)
        if os.path.isfile(path):
            stat = os.stat(path)
            files.append({
                'name': name,
                'size': stat.st_size,
                'size_str': _file_size_str(stat.st_size),
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'content_type': _guess_mime(name),
                'icon': _file_icon(name),
                'ext': name.rsplit('.', 1)[-1].upper() if '.' in name else 'FILE',
            })
    return sorted(files, key=lambda f: f['modified'], reverse=True)


# ── API JSON (usada por el servidor atacante para hacer proxy) ─────────────────

@app.route('/api/files', methods=['GET'])
def api_files():
    """
    Endpoint JSON que consume el servidor atacante (app.py) como proxy.
    Devuelve la lista de archivos sin data_b64.
    """
    try:
        files = _list_files()
        # Quitar icon del JSON (solo útil en HTML)
        for f in files:
            f.pop('icon', None)
        total_bytes = sum(f['size'] for f in files)
        return jsonify({
            'success': True,
            'files': files,
            'total': len(files),
            'total_bytes': total_bytes,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/download/<path:filename>', methods=['GET'])
def api_download(filename):
    """Endpoint de descarga usado por el proxy del atacante."""
    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'Archivo no encontrado.'}), 404


# ── HTML para la víctima ───────────────────────────────────────────────────────

HTML_PAGE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FileShare — Máquina Víctima</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:           #0a0a0f;
            --card:         rgba(255,255,255,0.04);
            --card-h:       rgba(255,255,255,0.07);
            --border:       rgba(255,255,255,0.08);
            --red:          #e94560;
            --cyan:         #00d4ff;
            --green:        #00ff9d;
            --amber:        #f0a500;
            --text:         #e8e8f0;
            --muted:        #7a7a9a;
            --dim:          #4a4a6a;
        }
        *{box-sizing:border-box;margin:0;padding:0;}
        body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;min-height:100vh;overflow-x:hidden;}
        body::before{content:'';position:fixed;inset:0;
            background-image:linear-gradient(rgba(233,69,96,.04)1px,transparent 1px),linear-gradient(90deg,rgba(233,69,96,.04)1px,transparent 1px);
            background-size:40px 40px;pointer-events:none;z-index:0;}
        .scanline{position:fixed;top:0;left:0;right:0;height:2px;
            background:linear-gradient(90deg,transparent,var(--red),transparent);
            animation:scan 4s linear infinite;opacity:.4;pointer-events:none;z-index:100;}
        @keyframes scan{0%{top:0}100%{top:100vh}}
        .wrap{position:relative;z-index:1;max-width:860px;margin:0 auto;padding:2rem 1.5rem 4rem;}

        /* Header */
        .hdr{text-align:center;margin-bottom:2rem;}
        .badge{display:inline-block;background:rgba(233,69,96,.12);border:1px solid rgba(233,69,96,.35);
            color:var(--red);font-size:.7rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
            padding:4px 14px;border-radius:20px;margin-bottom:.9rem;}
        .hdr h1{font-size:2rem;font-weight:700;
            background:linear-gradient(135deg,#e94560,#ff6b9d,#00d4ff);
            -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
            margin-bottom:.3rem;}
        .hdr p{color:var(--muted);font-size:.88rem;}
        .ip-chip{display:inline-flex;align-items:center;gap:6px;margin-top:.7rem;
            background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.25);color:var(--cyan);
            font-family:'JetBrains Mono',monospace;font-size:.78rem;padding:4px 14px;border-radius:20px;}

        /* Warning */
        .warn{background:rgba(240,165,0,.08);border:1px solid rgba(240,165,0,.3);border-radius:8px;
            padding:.7rem 1rem;display:flex;align-items:flex-start;gap:.6rem;font-size:.83rem;
            color:var(--amber);margin-bottom:1.5rem;}

        /* Card */
        .card{background:var(--card);border:1px solid var(--border);border-radius:14px;
            padding:1.6rem;margin-bottom:1.3rem;backdrop-filter:blur(12px);transition:border-color .2s;}
        .card:hover{border-color:rgba(255,255,255,.13);}
        .card-title{font-size:.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
            color:var(--muted);margin-bottom:1.1rem;display:flex;align-items:center;gap:.5rem;}

        /* Upload zone */
        .dropzone{border:2px dashed rgba(233,69,96,.35);border-radius:10px;padding:2.2rem 1.5rem;
            text-align:center;cursor:pointer;transition:border-color .2s,background .2s;position:relative;}
        .dropzone:hover,.dropzone.over{border-color:var(--red);background:rgba(233,69,96,.06);}
        .dropzone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;}
        .dropzone .dicon{font-size:2.2rem;margin-bottom:.6rem;}
        .dropzone .dtext{color:var(--muted);font-size:.88rem;}
        .dropzone .dtext strong{color:var(--text);}
        .btn-up{margin-top:.9rem;background:linear-gradient(135deg,#e94560,#c73652);color:#fff;
            border:none;padding:.6rem 1.6rem;border-radius:7px;font-size:.85rem;font-weight:700;
            letter-spacing:.06em;cursor:pointer;transition:opacity .15s,transform .1s;
            box-shadow:0 0 18px rgba(233,69,96,.3);}
        .btn-up:hover{opacity:.85;transform:translateY(-1px);}
        .btn-up:active{transform:translateY(0);}
        .btn-up:disabled{opacity:.5;cursor:not-allowed;}

        /* Flash */
        .flash{padding:.65rem 1rem;border-radius:7px;font-size:.84rem;margin-bottom:1rem;}
        .flash.ok{background:rgba(0,255,157,.08);border:1px solid rgba(0,255,157,.3);color:var(--green);}
        .flash.err{background:rgba(233,69,96,.08);border:1px solid rgba(233,69,96,.3);color:var(--red);}

        /* File list */
        .flist{display:flex;flex-direction:column;gap:.55rem;}
        .fitem{display:flex;align-items:center;gap:.85rem;background:var(--card);border:1px solid var(--border);
            border-radius:9px;padding:.8rem .95rem;transition:background .15s,border-color .15s,transform .15s;
            animation:slIn .22s ease;}
        @keyframes slIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
        .fitem:hover{background:var(--card-h);border-color:rgba(255,255,255,.13);transform:translateX(3px);}
        .fitem .ico{font-size:1.5rem;flex-shrink:0;}
        .fitem .inf{flex:1;min-width:0;}
        .fitem .fname{font-size:.86rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
            font-family:'JetBrains Mono',monospace;}
        .fitem .fmeta{font-size:.73rem;color:var(--muted);margin-top:2px;}
        .fitem .fsz{font-size:.76rem;color:var(--cyan);font-family:'JetBrains Mono',monospace;
            white-space:nowrap;flex-shrink:0;}
        .btn-dl{flex-shrink:0;display:inline-flex;align-items:center;gap:4px;
            background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);color:var(--cyan);
            padding:5px 11px;border-radius:6px;font-size:.76rem;font-weight:700;text-decoration:none;
            transition:background .15s,transform .1s;}
        .btn-dl:hover{background:rgba(0,212,255,.18);transform:translateY(-1px);}

        /* Empty */
        .empty{text-align:center;padding:2rem 0;color:var(--dim);}
        .empty .eico{font-size:2.2rem;margin-bottom:.4rem;}

        /* Stats */
        .stats{display:flex;gap:.75rem;margin-bottom:1rem;flex-wrap:wrap;}
        .chip{display:flex;align-items:center;gap:5px;background:rgba(255,255,255,.04);
            border:1px solid var(--border);border-radius:20px;padding:3px 11px;
            font-size:.76rem;color:var(--muted);}
        .chip span{color:var(--text);font-weight:600;}
    </style>
</head>
<body>
<div class="scanline"></div>
<div class="wrap">
    <div class="hdr">
        <div class="badge">🎯 Máquina Víctima — Modo Laboratorio</div>
        <h1>📂 FileShare Server</h1>
        <p>Servidor de transferencia de archivos — HTTP sin cifrar (puerto 5001)</p>
        <div class="ip-chip">🌐 Escuchando en 0.0.0.0:5001</div>
    </div>

    <div class="warn">
        <span>⚠️</span>
        <span><strong>MODO EDUCATIVO:</strong> Este servidor transfiere archivos en
        <strong>HTTP plano</strong>. El tráfico puede ser interceptado. El servidor
        atacante puede ver y descargar estos archivos remotamente desde su CyberTool.</span>
    </div>

    {% if message %}
    <div class="flash {{ 'ok' if ok else 'err' }}">{{ message }}</div>
    {% endif %}

    <div class="card">
        <div class="card-title">⬆️ Subir Archivo al Servidor</div>
        <form method="post" enctype="multipart/form-data" id="upform">
            <div class="dropzone" id="dz">
                <input type="file" name="file" id="finput" onchange="updateLabel(this)">
                <div class="dicon">📤</div>
                <div class="dtext"><strong id="flabel">Arrastra un archivo aquí</strong><br>o haz clic para seleccionar</div>
                <button type="submit" class="btn-up" id="ubtn">SUBIR ARCHIVO</button>
            </div>
        </form>
    </div>

    <div class="card">
        <div class="card-title">📋 Archivos en este Servidor</div>

        {% if files %}
        <div class="stats">
            <div class="chip">📁 Archivos: <span>{{ files|length }}</span></div>
            <div class="chip">📦 Espacio: <span>{{ total_size }}</span></div>
            <div class="chip">🕐 Último: <span>{{ files[0].modified if files else '—' }}</span></div>
        </div>
        <div class="flist">
            {% for f in files %}
            <div class="fitem">
                <span class="ico">{{ f.icon }}</span>
                <div class="inf">
                    <div class="fname">{{ f.name }}</div>
                    <div class="fmeta">{{ f.modified }} · {{ f.ext }}</div>
                </div>
                <span class="fsz">{{ f.size_str }}</span>
                <a href="/api/download/{{ f.name }}" class="btn-dl" download="{{ f.name }}">⬇️ Descargar</a>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <div class="empty">
            <div class="eico">📭</div>
            <p>No hay archivos subidos aún</p>
        </div>
        {% endif %}
    </div>
</div>
<script>
    function updateLabel(input) {
        if (input.files && input.files[0])
            document.getElementById('flabel').textContent = '📎 ' + input.files[0].name;
    }
    const dz = document.getElementById('dz');
    ['dragenter','dragover'].forEach(e => dz.addEventListener(e, ev => { ev.preventDefault(); dz.classList.add('over'); }));
    ['dragleave','drop'].forEach(e => dz.addEventListener(e, ev => dz.classList.remove('over')));
    document.getElementById('upform').addEventListener('submit', () => {
        const b = document.getElementById('ubtn');
        b.disabled = true; b.textContent = '⏳ SUBIENDO...';
    });
</script>
</body>
</html>"""


# ── Web UI para la víctima ─────────────────────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
def index():
    message = None
    ok = True

    if request.method == 'POST':
        if 'file' not in request.files:
            message = '❌ No se encontró ningún archivo en la solicitud.'
            ok = False
        else:
            file = request.files['file']
            if not file.filename:
                message = '❌ No seleccionaste ningún archivo.'
                ok = False
            else:
                dest = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(dest)
                size = os.path.getsize(dest)
                message = f'✅ Archivo "{file.filename}" subido correctamente ({_file_size_str(size)}).'
                ok = True

    files = _list_files()
    total_size = _file_size_str(sum(f['size'] for f in files))

    return render_template_string(
        HTML_PAGE,
        files=files,
        total_size=total_size,
        message=message,
        ok=ok,
    )


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  📂 FileShare — Servidor de la Máquina VÍCTIMA")
    print("=" * 60)
    print("  UI local:         http://localhost:5001")
    print("  API para atacante: http://0.0.0.0:5001/api/files")
    print("  ⚠️  Tráfico HTTP plano — visible al sniffer del atacante")
    print("=" * 60 + "\n")
    app.run(host='0.0.0.0', port=5001, debug=True)