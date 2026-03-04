// --- DOM Elements ---
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

// --- Global State ---
let peer = null;
let conn = null;
let localKeyPair = null;
let sharedAESKey = null;

// File Receiving State
let receiveBuffer = [];
let incomingMeta = null;
let receivedBytes = 0;

const CHUNK_SIZE = 64 * 1024; // 64KB per chunk to prevent WebRTC channel overflow

// =====================================================================
// 1. Web Crypto API: Key Generation & Derivation
// =====================================================================

async function initCrypto() {
    // Generate an Elliptic Curve Diffie-Hellman (ECDH) key pair
    localKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true, 
        ["deriveKey"]
    );
}

async function deriveAESKey(peerJwk) {
    // Import the peer's public key
    const peerPubKey = await crypto.subtle.importKey(
        "jwk", 
        peerJwk, 
        { name: "ECDH", namedCurve: "P-256" }, 
        true, 
        []
    );
    // Mathematically mix our private key with their public key to get a shared AES key
    return await crypto.subtle.deriveKey(
        { name: "ECDH", public: peerPubKey },
        localKeyPair.privateKey,
        { name: "AES-GCM", length: 256 },
        true, 
        ["encrypt", "decrypt"]
    );
}

// =====================================================================
// 2. PeerJS & WebRTC Setup
// =====================================================================

async function initPeer() {
    await initCrypto();

    // Initialize PeerJS (Connects to their free cloud signaling server)
    peer = new Peer({ debug: 2 });

    peer.on('open', (id) => {
        myPeerIdEl.textContent = id;
    });

    // Handle Incoming Connections (When someone pastes your ID)
    peer.on('connection', (connection) => {
        if (conn) {
            connection.close(); // Only allow one connection at a time
            return;
        }
        conn = connection;
        setupConnectionHandlers();
    });

    peer.on('error', (err) => {
        console.error(err);
        alert('Connection Error: ' + err.type);
    });
}

function setupConnectionHandlers() {
    conn.on('open', async () => {
        updateStatus(true);
        
        // Export our public key and send it to the peer
        const exportedPubKey = await crypto.subtle.exportKey("jwk", localKeyPair.publicKey);
        conn.send({ type: 'PUB_KEY', key: exportedPubKey });
    });

    conn.on('data', async (msg) => {
        // Step 1: Handshake & Key Exchange
        if (msg.type === 'PUB_KEY') {
            sharedAESKey = await deriveAESKey(msg.key);
            console.log("Secure AES-GCM Key Derived Successfully!");
            showTransferUI();
        } 
        // Step 2: Incoming File Metadata
        else if (msg.type === 'META') {
            incomingMeta = msg;
            receiveBuffer = [];
            receivedBytes = 0;
            progressContainer.style.display = 'block';
            transferLabel.textContent = `Receiving: ${msg.name}...`;
        } 
        // Step 3: Incoming Encrypted File Chunk
        else if (msg.type === 'CHUNK') {
            try {
                const iv = new Uint8Array(msg.iv);
                const decryptedBuffer = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv }, 
                    sharedAESKey, 
                    msg.data
                );
                receiveBuffer.push(decryptedBuffer);
                receivedBytes += msg.originalSize; // Track based on pre-encrypted size
                updateProgress(receivedBytes, incomingMeta.size);
            } catch (err) {
                console.error("Decryption failed. Data tampered or key mismatch.", err);
            }
        } 
        // Step 4: End of File
        else if (msg.type === 'EOF') {
            transferLabel.textContent = "Decrypting & Reassembling...";
            setTimeout(() => {
                const blob = new Blob(receiveBuffer, { type: incomingMeta.fileType });
                createDownloadableFile(blob, incomingMeta.name);
                
                transferLabel.textContent = "Transfer Complete!";
                progressBar.style.background = "#10b981"; // Green success
                setTimeout(() => { progressContainer.style.display = 'none'; }, 3000);
            }, 500);
        }
    });

    conn.on('close', () => {
        updateStatus(false);
        alert("Peer disconnected.");
        location.reload(); // Quick reset for mobile
    });
}

// =====================================================================
// 3. File Processing & Sending
// =====================================================================

fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file || !sharedAESKey || !conn) return;

    // Reset UI
    progressContainer.style.display = 'block';
    transferLabel.textContent = `Encrypting & Sending: ${file.name}...`;
    progressBar.style.background = "var(--gradient-brand)";
    
    // Send Metadata
    conn.send({ type: 'META', name: file.name, size: file.size, fileType: file.type });

    let offset = 0;
    
    // Read and Encrypt in Chunks to save RAM
    while (offset < file.size) {
        const chunk = file.slice(offset, offset + CHUNK_SIZE);
        const arrayBuffer = await chunk.arrayBuffer();
        
        // Generate a random 12-byte IV for EVERY chunk for maximum AES-GCM security
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encryptedChunk = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, 
            sharedAESKey, 
            arrayBuffer
        );

        // Send over WebRTC Data Channel
        conn.send({ 
            type: 'CHUNK', 
            iv: Array.from(iv), // PeerJS handles standard arrays better than typed arrays in JSON
            data: encryptedChunk,
            originalSize: arrayBuffer.byteLength
        });

        offset += CHUNK_SIZE;
        updateProgress(offset, file.size);
        
        // Yield to main thread so UI doesn't freeze on mobile
        await new Promise(r => setTimeout(r, 5)); 
    }

    conn.send({ type: 'EOF' });
    transferLabel.textContent = "Sent successfully!";
    progressBar.style.background = "#10b981";
    fileInput.value = ''; // clear input
});

// =====================================================================
// 4. UI & Utility Functions
// =====================================================================

connectBtn.addEventListener('click', () => {
    const targetId = targetPeerIdInput.value.trim();
    if (!targetId) return;
    
    connectBtn.textContent = "Connecting...";
    conn = peer.connect(targetId, { reliable: true });
    setupConnectionHandlers();
});

copyIdBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(myPeerIdEl.textContent);
    const originalIcon = copyIdBtn.innerHTML;
    copyIdBtn.innerHTML = '<i data-lucide="check" style="color: #10b981;"></i>';
    lucide.createIcons();
    setTimeout(() => {
        copyIdBtn.innerHTML = originalIcon;
        lucide.createIcons();
    }, 2000);
});

function updateStatus(isConnected) {
    if (isConnected) {
        statusDot.className = 'dot connected';
        connectionStatus.lastChild.textContent = ' Connected';
    } else {
        statusDot.className = 'dot disconnected';
        connectionStatus.lastChild.textContent = ' Waiting...';
    }
}

function showTransferUI() {
    // Anime.js transition
    anime({
        targets: '#setupSection',
        opacity: 0,
        translateY: -20,
        duration: 400,
        easing: 'easeInQuad',
        complete: () => {
            setupSection.style.display = 'none';
            transferSection.style.display = 'block';
            anime({
                targets: '#transferSection',
                opacity: [0, 1],
                translateY: [20, 0],
                duration: 600,
                easing: 'easeOutExpo'
            });
        }
    });
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
    fileItem.innerHTML = `
        <a href="${url}" download="${filename}">
            <i data-lucide="file-check"></i> 
            ${filename} (Decrypted)
        </a>
        <span style="color: var(--text-muted); font-size: 0.8rem;">Ready</span>
    `;
    
    receivedFilesDiv.appendChild(fileItem);
    lucide.createIcons();
}

// Bootstrap Application
initPeer();
