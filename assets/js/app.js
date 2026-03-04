const myPeerIdEl = document.getElementById('myPeerId');
const targetPeerIdInput = document.getElementById('targetPeerId');
const connectBtn = document.getElementById('connectBtn');
const copyIdBtn = document.getElementById('copyIdBtn');
const connectionStatus = document.getElementById('connectionStatus');
const statusDot = connectionStatus.querySelector('.dot');
const setupSection = document.getElementById('setupSection');
const transferSection = document.getElementById('transferSection');
const fileInput = document.getElementById('fileInput');
const progressContainer = document.getElementById('progressContainer');
const progressBar = document.getElementById('progressBar');
const transferPercent = document.getElementById('transferPercent');
const transferLabel = document.getElementById('transferLabel');
const receivedFilesDiv = document.getElementById('receivedFiles');
const tabApp = document.getElementById('tabApp');
const tabHistory = document.getElementById('tabHistory');
const appView = document.getElementById('appView');
const historyView = document.getElementById('historyView');
const historyList = document.getElementById('historyList');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

let peer = null;
let conn = null;
let localKeyPair = null;
let sharedAESKey = null;
let receiveBuffer = [];
let incomingMeta = null;
let receivedBytes = 0;
const CHUNK_SIZE = 64 * 1024;

function saveHistory(action, details) {
    const history = JSON.parse(localStorage.getItem('zeroShareHistory') || '[]');
    history.unshift({ action, details, time: new Date().toLocaleString() });
    localStorage.setItem('zeroShareHistory', JSON.stringify(history));
    renderHistory();
}

function renderHistory() {
    if(!historyList) return;
    const history = JSON.parse(localStorage.getItem('zeroShareHistory') || '[]');
    if(history.length === 0) {
        historyList.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:1rem;">No history found.</div>';
        return;
    }
    historyList.innerHTML = history.map(item => `
        <div class="history-item">
            <span class="history-action">${item.action}</span>
            <span>${item.details}</span>
            <span class="history-time">${item.time}</span>
        </div>
    `).join('');
}

if(clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
        localStorage.removeItem('zeroShareHistory');
        renderHistory();
    });
}

if(tabApp && tabHistory) {
    tabApp.addEventListener('click', () => {
        tabApp.classList.add('active');
        tabHistory.classList.remove('active');
        appView.style.display = 'block';
        historyView.style.display = 'none';
    });
    tabHistory.addEventListener('click', () => {
        tabHistory.classList.add('active');
        tabApp.classList.remove('active');
        appView.style.display = 'none';
        historyView.style.display = 'block';
        renderHistory();
    });
}

async function initCrypto() {
    localKeyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
}

async function deriveAESKey(peerJwk) {
    const peerPubKey = await crypto.subtle.importKey("jwk", peerJwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
    return await crypto.subtle.deriveKey({ name: "ECDH", public: peerPubKey }, localKeyPair.privateKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

function generateShortCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 6; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    return result;
}

async function initPeer() {
    await initCrypto();
    const shortId = generateShortCode();
    const peerConfig = {
        debug: 2,
        config: {
            'iceServers': [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: "stun:stun.relay.metered.ca:80" },
                { urls: "turn:global.relay.metered.ca:80", username: "720b913bfa71fc6b933ac20a", credential: "MROrNaIhYikme2P4" },
                { urls: "turn:global.relay.metered.ca:80?transport=tcp", username: "720b913bfa71fc6b933ac20a", credential: "MROrNaIhYikme2P4" },
                { urls: "turn:global.relay.metered.ca:443", username: "720b913bfa71fc6b933ac20a", credential: "MROrNaIhYikme2P4" },
                { urls: "turns:global.relay.metered.ca:443?transport=tcp", username: "720b913bfa71fc6b933ac20a", credential: "MROrNaIhYikme2P4" }
            ]
        }
    };
    peer = new Peer(shortId, peerConfig);
    peer.on('open', (id) => { if(myPeerIdEl) myPeerIdEl.textContent = id; });
    peer.on('disconnected', () => { if (!peer.destroyed) peer.reconnect(); });
    peer.on('connection', (connection) => {
        if (conn) { connection.close(); return; }
        conn = connection;
        setupConnectionHandlers();
    });
    peer.on('error', (err) => {
        if(connectBtn) { connectBtn.textContent = "Connect"; connectBtn.disabled = false; }
    });
    renderHistory();
}

function setupConnectionHandlers() {
    conn.on('open', async () => {
        updateStatus(true);
        if(connectBtn) connectBtn.textContent = "Connected";
        saveHistory('Connected', `Established secure tunnel with Peer ID: ${conn.peer}`);
        const exportedPubKey = await crypto.subtle.exportKey("jwk", localKeyPair.publicKey);
        conn.send({ type: 'PUB_KEY', key: exportedPubKey });
    });
    conn.on('data', async (msg) => {
        if (msg.type === 'PUB_KEY') {
            sharedAESKey = await deriveAESKey(msg.key);
            showTransferUI();
        } else if (msg.type === 'META') {
            incomingMeta = msg; receiveBuffer = []; receivedBytes = 0;
            progressContainer.style.display = 'block';
            transferLabel.textContent = `Receiving: ${msg.name}...`;
        } else if (msg.type === 'CHUNK') {
            try {
                const iv = new Uint8Array(msg.iv);
                const decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, sharedAESKey, msg.data);
                receiveBuffer.push(decryptedBuffer);
                receivedBytes += msg.originalSize;
                updateProgress(receivedBytes, incomingMeta.size);
            } catch (err) {}
        } else if (msg.type === 'EOF') {
            transferLabel.textContent = "Decrypting...";
            setTimeout(() => {
                const blob = new Blob(receiveBuffer, { type: incomingMeta.fileType });
                createDownloadableFile(blob, incomingMeta.name);
                saveHistory('Received File', `Name: ${incomingMeta.name}, Size: ${(incomingMeta.size/1024/1024).toFixed(2)} MB`);
                transferLabel.textContent = "Complete!";
                progressBar.style.background = "#10b981";
                setTimeout(() => { progressContainer.style.display = 'none'; }, 3000);
            }, 500);
        }
    });
    conn.on('close', () => { updateStatus(false); location.reload(); });
}

if(fileInput) {
    fileInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file || !sharedAESKey || !conn) return;
        progressContainer.style.display = 'block';
        transferLabel.textContent = `Sending: ${file.name}...`;
        progressBar.style.background = "var(--gradient-brand)";
        conn.send({ type: 'META', name: file.name, size: file.size, fileType: file.type });
        let offset = 0;
        while (offset < file.size) {
            const chunk = file.slice(offset, offset + CHUNK_SIZE);
            const arrayBuffer = await chunk.arrayBuffer();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedChunk = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, sharedAESKey, arrayBuffer);
            conn.send({ type: 'CHUNK', iv: Array.from(iv), data: encryptedChunk, originalSize: arrayBuffer.byteLength });
            offset += CHUNK_SIZE;
            updateProgress(offset, file.size);
            await new Promise(r => setTimeout(r, 5));
        }
        conn.send({ type: 'EOF' });
        saveHistory('Sent File', `Name: ${file.name}, Size: ${(file.size/1024/1024).toFixed(2)} MB`);
        transferLabel.textContent = "Sent successfully!";
        progressBar.style.background = "#10b981";
        fileInput.value = '';
    });
}

if(connectBtn) {
    connectBtn.addEventListener('click', () => {
        const targetId = targetPeerIdInput.value.trim().toUpperCase();
        if (!targetId) return;
        connectBtn.textContent = "Connecting...";
        connectBtn.disabled = true;
        conn = peer.connect(targetId, { reliable: true });
        setTimeout(() => {
            if (statusDot.className !== 'dot connected') {
                connectBtn.textContent = "Connect"; connectBtn.disabled = false;
                if (conn) conn.close();
            }
        }, 10000);
        setupConnectionHandlers();
    });
}

if(copyIdBtn) {
    copyIdBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(myPeerIdEl.textContent);
        const originalIcon = copyIdBtn.innerHTML;
        copyIdBtn.innerHTML = '<i data-lucide="check" style="color: #10b981;"></i>';
        lucide.createIcons();
        setTimeout(() => { copyIdBtn.innerHTML = originalIcon; lucide.createIcons(); }, 2000);
    });
}

function updateStatus(isConnected) {
    if(!statusDot) return;
    if (isConnected) { statusDot.className = 'dot connected'; connectionStatus.lastChild.textContent = ' Connected'; } 
    else { statusDot.className = 'dot disconnected'; connectionStatus.lastChild.textContent = ' Waiting...'; }
}

function showTransferUI() {
    setupSection.style.display = 'none';
    transferSection.style.display = 'block';
}

function updateProgress(current, total) {
    const percent = Math.min(Math.round((current / total) * 100), 100);
    progressBar.style.width = `${percent}%`;
    transferPercent.textContent = `${percent}%`;
}

function createDownloadableFile(blob, filename) {
    const url = URL.createObjectURL(blob);
    const fileItem = document.createElement('div');
    fileItem.className = 'received-item';
    fileItem.innerHTML = `<a href="${url}" download="${filename}"><i data-lucide="file-check"></i> ${filename}</a>`;
    receivedFilesDiv.appendChild(fileItem);
    lucide.createIcons();
}

if(myPeerIdEl) initPeer();
