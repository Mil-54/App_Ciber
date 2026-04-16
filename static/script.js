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

        if (data.packets.length === 0) {
            resultsBody.innerHTML = `
                <tr>
                    <td colspan="7" class="no-results">
                        <span class="no-results__icon">📭</span>
                        No se capturaron paquetes
                    </td>
                </tr>
            `;
        } else {
            data.packets.forEach((pkt, index) => {
                const protocolClass = getProtocolClass(pkt.protocol);
                const time = pkt.timestamp ? pkt.timestamp.split(' ')[1] : '-';
                const src = pkt.src_ip ? `${pkt.src_ip}:${pkt.src_port}` : '-';
                const dst = pkt.dst_ip ? `${pkt.dst_ip}:${pkt.dst_port}` : '-';

                resultsBody.innerHTML += `
                    <tr>
                        <td class="port-number">${index + 1}</td>
                        <td>${time}</td>
                        <td><span class="protocol-badge ${protocolClass}">${pkt.protocol}</span></td>
                        <td>${escapeHtml(src)}</td>
                        <td>${escapeHtml(dst)}</td>
                        <td>${escapeHtml(pkt.service || '-')}</td>
                        <td>${pkt.size} B</td>
                    </tr>
                `;
            });
        }

        sniffResults.classList.add('visible');
    }

    function getProtocolClass(protocol) {
        const map = {
            'TCP': 'protocol-tcp',
            'UDP': 'protocol-udp',
            'ICMP': 'protocol-icmp'
        };
        return map[protocol] || 'protocol-other';
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
