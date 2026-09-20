const myPeerIdEl = document.getElementById("myPeerId");
const targetPeerIdEl = document.getElementById("targetPeerId");
const connectBtn = document.getElementById("connectBtn");
const copyIdBtn = document.getElementById("copyIdBtn");
const connectionStatus = document.getElementById("connectionStatus");
const statusDot = document.getElementById("statusDot");
const setupSection = document.getElementById("setupSection");
const transferSection = document.getElementById("transferSection");
const fileInput = document.getElementById("fileInput");

const fileNameEl = document.getElementById("fileName");
const fileSizeEl = document.getElementById("fileSize");
const uploadProgress = document.getElementById("uploadProgress");
const uploadProgressText = document.getElementById("uploadProgressText");
const uploadStatus = document.getElementById("uploadStatus");

const receivedFilesEl = document.getElementById("receivedFiles");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

const tabs = document.querySelectorAll("[data-tab]");
const tabViews = document.querySelectorAll("[data-view]");

const CHUNK_SIZE = 16 * 1024;
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;
const CONNECTION_TIMEOUT = 15000;

let peer = null;
let conn = null;
let localKeyPair = null;
let sharedAESKey = null;

let receiveBuffer = [];
let incomingMeta = null;
let receivedBytes = 0;
let incomingChunks = 0;

let transferInProgress = false;
let connectionTimer = null;

function setStatus(message, type = "idle") {
    if (connectionStatus) {
        connectionStatus.textContent = message;
    }

    if (statusDot) {
        statusDot.className = "status-dot";

        if (type === "connected") {
            statusDot.classList.add("connected");
        } else if (type === "connecting") {
            statusDot.classList.add("connecting");
        } else if (type === "error") {
            statusDot.classList.add("error");
        }
    }
}

function updateConnectionStatus(message, type = "idle") {
    setStatus(message, type);
}

function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) {
        return "0 Bytes";
    }

    const units = ["Bytes", "KB", "MB", "GB", "TB"];
    const index = Math.min(
        Math.floor(Math.log(bytes) / Math.log(1024)),
        units.length - 1
    );

    return `${(bytes / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function generateShortCode(length = 8) {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const values = new Uint32Array(length);

    crypto.getRandomValues(values);

    let result = "";

    for (let i = 0; i < length; i++) {
        result += chars[values[i] % chars.length];
    }

    return result;
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    const chunkSize = 0x8000;

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(
            ...bytes.subarray(i, i + chunkSize)
        );
    }

    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

function concatArrayBuffers(buffers) {
    const totalLength = buffers.reduce(
        (total, buffer) => total + buffer.byteLength,
        0
    );

    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const buffer of buffers) {
        const bytes = new Uint8Array(buffer);
        result.set(bytes, offset);
        offset += bytes.byteLength;
    }

    return result.buffer;
}

async function generateKeyPair() {
    return crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        false,
        ["deriveKey"]
    );
}

async function exportPublicKey(publicKey) {
    return crypto.subtle.exportKey("jwk", publicKey);
}

async function importPublicKey(jwk) {
    return crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        true,
        []
    );
}

async function deriveSharedKey(publicKey) {
    if (!localKeyPair?.privateKey) {
        throw new Error("Local key pair is unavailable");
    }

    return crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: publicKey,
        },
        localKeyPair.privateKey,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptData(data) {
    if (!sharedAESKey) {
        throw new Error("Encryption key is not available");
    }

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv,
        },
        sharedAESKey,
        data
    );

    return {
        iv: arrayBufferToBase64(iv.buffer),
        data: arrayBufferToBase64(encrypted),
    };
}

async function decryptData(payload) {
    if (!sharedAESKey) {
        throw new Error("Decryption key is not available");
    }

    if (
        !payload ||
        typeof payload.iv !== "string" ||
        typeof payload.data !== "string"
    ) {
        throw new Error("Invalid encrypted payload");
    }

    const iv = new Uint8Array(base64ToArrayBuffer(payload.iv));
    const encrypted = base64ToArrayBuffer(payload.data);

    if (iv.byteLength !== 12) {
        throw new Error("Invalid IV");
    }

    return crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv,
        },
        sharedAESKey,
        encrypted
    );
}

async function getIceServers() {
    const response = await fetch("/api/turn-credentials", {
        method: "GET",
        cache: "no-store",
        headers: {
            Accept: "application/json",
        },
    });

    if (!response.ok) {
        throw new Error("Failed to obtain TURN configuration");
    }

    const data = await response.json();

    if (
        !data ||
        !Array.isArray(data.iceServers) ||
        data.iceServers.length === 0
    ) {
        throw new Error("No ICE servers available");
    }

    return data.iceServers;
}

function resetTransferState() {
    receiveBuffer = [];
    incomingMeta = null;
    receivedBytes = 0;
    incomingChunks = 0;
    transferInProgress = false;
}

function updateUploadProgress(percent, text = "") {
    if (uploadProgress) {
        uploadProgress.value = percent;
        uploadProgress.style.width = `${percent}%`;
    }

    if (uploadProgressText) {
        uploadProgressText.textContent =
            text || `${Math.round(percent)}%`;
    }
}

function updateUploadStatus(message) {
    if (uploadStatus) {
        uploadStatus.textContent = message;
    }
}

function showTransferSection() {
    if (setupSection) {
        setupSection.style.display = "none";
    }

    if (transferSection) {
        transferSection.style.display = "";
    }
}

function showSetupSection() {
    if (setupSection) {
        setupSection.style.display = "";
    }

    if (transferSection) {
        transferSection.style.display = "none";
    }
}

function clearConnectionTimer() {
    if (connectionTimer) {
        clearTimeout(connectionTimer);
        connectionTimer = null;
    }
}

function startConnectionTimer() {
    clearConnectionTimer();

    connectionTimer = setTimeout(() => {
        if (!conn || !conn.open) {
            setStatus("Connection timed out", "error");
        }
    }, CONNECTION_TIMEOUT);
}

function saveHistory(item) {
    try {
        const history = JSON.parse(
            localStorage.getItem("zeroshare_history") || "[]"
        );

        history.unshift({
            ...item,
            timestamp: Date.now(),
        });

        localStorage.setItem(
            "zeroshare_history",
            JSON.stringify(history.slice(0, 50))
        );

        renderHistory();
    } catch (error) {
        console.error("History error:", error);
    }
}

function renderHistory() {
    if (!historyList) {
        return;
    }

    historyList.replaceChildren();

    let history = [];

    try {
        history = JSON.parse(
            localStorage.getItem("zeroshare_history") || "[]"
        );
    } catch {
        history = [];
    }

    if (!history.length) {
        const empty = document.createElement("div");
        empty.className = "history-empty";
        empty.textContent = "No transfer history";
        historyList.appendChild(empty);
        return;
    }

    for (const item of history) {
        const wrapper = document.createElement("div");
        wrapper.className = "history-item";

        const name = document.createElement("div");
        name.className = "history-name";
        name.textContent = item.name || "Unknown file";

        const details = document.createElement("div");
        details.className = "history-details";

        const direction = item.direction === "received"
            ? "Received"
            : "Sent";

        const size = formatBytes(Number(item.size) || 0);
        const date = item.timestamp
            ? new Date(item.timestamp).toLocaleString()
            : "";

        details.textContent = `${direction} · ${size} · ${date}`;

        wrapper.appendChild(name);
        wrapper.appendChild(details);
        historyList.appendChild(wrapper);
    }
}

function addReceivedFile(fileData) {
    if (!receivedFilesEl) {
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "received-file";

    const name = document.createElement("div");
    name.className = "received-file-name";
    name.textContent = fileData.name;

    const details = document.createElement("div");
    details.className = "received-file-details";
    details.textContent = `${formatBytes(fileData.size)} · ${fileData.type || "File"}`;

    const downloadBtn = document.createElement("button");
    downloadBtn.type = "button";
    downloadBtn.textContent = "Download";

    downloadBtn.addEventListener("click", () => {
        const url = URL.createObjectURL(fileData.blob);

        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = fileData.name || "download";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();

        setTimeout(() => {
            URL.revokeObjectURL(url);
        }, 1000);
    });

    wrapper.appendChild(name);
    wrapper.appendChild(details);
    wrapper.appendChild(downloadBtn);

    receivedFilesEl.prepend(wrapper);
}

async function sendPublicKey() {
    if (!conn || !conn.open) {
        throw new Error("Connection is not open");
    }

    if (!localKeyPair) {
        localKeyPair = await generateKeyPair();
    }

    const publicKey = await exportPublicKey(localKeyPair.publicKey);

    conn.send({
        type: "KEY",
        key: publicKey,
    });
}

async function handleKeyMessage(message) {
    if (!message?.key) {
        throw new Error("Invalid public key");
    }

    const remotePublicKey = await importPublicKey(message.key);

    sharedAESKey = await deriveSharedKey(remotePublicKey);

    if (!localKeyPair) {
        localKeyPair = await generateKeyPair();
    }

    const localPublicKey = await exportPublicKey(localKeyPair.publicKey);

    if (conn?.open) {
        conn.send({
            type: "KEY_ACK",
            key: localPublicKey,
        });
    }

    setStatus("Secure connection established", "connected");
    showTransferSection();
}

async function sendFile(file) {
    if (!conn || !conn.open) {
        throw new Error("No active connection");
    }

    if (!sharedAESKey) {
        throw new Error("Secure key exchange is not complete");
    }

    if (!(file instanceof File)) {
        throw new Error("Invalid file");
    }

    if (file.size > MAX_FILE_SIZE) {
        throw new Error("File is too large");
    }

    transferInProgress = true;

    updateUploadProgress(0, "Preparing...");
    updateUploadStatus("Encrypting file metadata...");

    const metadata = {
        name: file.name,
        size: file.size,
        fileType: file.type || "application/octet-stream",
    };

    const encryptedMeta = await encryptData(
        new TextEncoder().encode(JSON.stringify(metadata))
    );

    conn.send({
        type: "META",
        ...encryptedMeta,
    });

    let offset = 0;

    while (offset < file.size) {
        if (!conn || !conn.open) {
            throw new Error("Connection closed during transfer");
        }

        const chunk = await file.slice(
            offset,
            Math.min(offset + CHUNK_SIZE, file.size)
        ).arrayBuffer();

        const encryptedChunk = await encryptData(chunk);

        conn.send({
            type: "CHUNK",
            ...encryptedChunk,
        });

        offset += chunk.byteLength;

        const percent = file.size === 0
            ? 100
            : (offset / file.size) * 100;

        updateUploadProgress(
            percent,
            `${Math.round(percent)}%`
        );

        updateUploadStatus(
            `${formatBytes(offset)} / ${formatBytes(file.size)}`
        );

        await new Promise(resolve => setTimeout(resolve, 0));
    }

    conn.send({
        type: "END",
    });

    updateUploadProgress(100, "100%");
    updateUploadStatus("File sent successfully");

    saveHistory({
        direction: "sent",
        name: file.name,
        size: file.size,
        type: file.type || "application/octet-stream",
    });

    transferInProgress = false;
}

async function handleMetaMessage(message) {
    const decrypted = await decryptData(message);

    let metadata;

    try {
        metadata = JSON.parse(
            new TextDecoder().decode(decrypted)
        );
    } catch {
        throw new Error("Invalid file metadata");
    }

    if (
        !metadata ||
        typeof metadata.name !== "string" ||
        typeof metadata.size !== "number" ||
        !Number.isSafeInteger(metadata.size) ||
        metadata.size < 0 ||
        metadata.size > MAX_FILE_SIZE
    ) {
        throw new Error("Invalid file metadata");
    }

    incomingMeta = {
        name: metadata.name.slice(0, 512),
        size: metadata.size,
        fileType:
            typeof metadata.fileType === "string"
                ? metadata.fileType.slice(0, 255)
                : "application/octet-stream",
    };

    receiveBuffer = [];
    receivedBytes = 0;
    incomingChunks = 0;

    updateUploadProgress(0, "0%");
    updateUploadStatus(
        `Receiving ${incomingMeta.name}...`
    );
}

async function handleChunkMessage(message) {
    if (!incomingMeta) {
        throw new Error("Received chunk before metadata");
    }

    const decrypted = await decryptData(message);
    const chunk = new Uint8Array(decrypted);

    if (chunk.byteLength === 0) {
        throw new Error("Empty chunk");
    }

    if (
        receivedBytes + chunk.byteLength >
        incomingMeta.size
    ) {
        throw new Error("Received data exceeds expected size");
    }

    receiveBuffer.push(decrypted);
    receivedBytes += chunk.byteLength;
    incomingChunks++;

    const percent = incomingMeta.size === 0
        ? 100
        : (receivedBytes / incomingMeta.size) * 100;

    updateUploadProgress(
        percent,
        `${Math.round(percent)}%`
    );

    updateUploadStatus(
        `${formatBytes(receivedBytes)} / ${formatBytes(incomingMeta.size)}`
    );
}

async function handleEndMessage() {
    if (!incomingMeta) {
        throw new Error("Received transfer completion without metadata");
    }

    if (receivedBytes !== incomingMeta.size) {
        throw new Error(
            `Incomplete transfer: received ${receivedBytes} of ${incomingMeta.size} bytes`
        );
    }

    const completeBuffer = concatArrayBuffers(receiveBuffer);

    if (completeBuffer.byteLength !== incomingMeta.size) {
        throw new Error("Received file size mismatch");
    }

    const blob = new Blob(
        [completeBuffer],
        {
            type: incomingMeta.fileType || "application/octet-stream",
        }
    );

    addReceivedFile({
        name: incomingMeta.name,
        size: incomingMeta.size,
        type: incomingMeta.fileType,
        blob,
    });

    saveHistory({
        direction: "received",
        name: incomingMeta.name,
        size: incomingMeta.size,
        type: incomingMeta.fileType,
    });

    updateUploadProgress(100, "100%");
    updateUploadStatus("File received successfully");

    resetTransferState();
}

async function handleConnectionMessage(message) {
    if (!message || typeof message.type !== "string") {
        return;
    }

    try {
        switch (message.type) {
            case "KEY":
                await handleKeyMessage(message);
                break;

            case "KEY_ACK":
                if (!message.key) {
                    throw new Error("Invalid key acknowledgement");
                }

                if (!localKeyPair) {
                    localKeyPair = await generateKeyPair();
                }

                sharedAESKey = await deriveSharedKey(
                    await importPublicKey(message.key)
                );

                clearConnectionTimer();
                setStatus("Secure connection established", "connected");
                showTransferSection();
                break;

            case "META":
                await handleMetaMessage(message);
                break;

            case "CHUNK":
                await handleChunkMessage(message);
                break;

            case "END":
                await handleEndMessage();
                break;

            default:
                break;
        }
    } catch (error) {
        console.error("Transfer error:", error);
        updateUploadStatus(error.message || "Transfer failed");
        setStatus("Transfer error", "error");
        resetTransferState();
    }
}

function setupConnection(connection) {
    conn = connection;

    clearConnectionTimer();
    startConnectionTimer();

    conn.binaryType = "arraybuffer";

    conn.on("open", async () => {
        clearConnectionTimer();

        setStatus("Connected, establishing encryption...", "connecting");

        try {
            sharedAESKey = null;

            if (!localKeyPair) {
                localKeyPair = await generateKeyPair();
            }

            await sendPublicKey();

            showTransferSection();
        } catch (error) {
            console.error("Key exchange failed:", error);
            setStatus("Secure connection failed", "error");
        }
    });

    conn.on("data", handleConnectionMessage);

    conn.on("close", () => {
        clearConnectionTimer();

        if (!transferInProgress) {
            setStatus("Connection closed", "idle");
        }

        sharedAESKey = null;
        conn = null;
    });

    conn.on("error", error => {
        console.error("Data connection error:", error);
        clearConnectionTimer();
        setStatus("Connection error", "error");
    });
}

async function connectToPeer() {
    const targetPeerId = targetPeerIdEl?.value?.trim();

    if (!targetPeerId) {
        setStatus("Enter a peer ID", "error");
        return;
    }

    if (!peer || peer.destroyed) {
        setStatus("Peer is not ready", "error");
        return;
    }

    if (targetPeerId === myPeerIdEl?.textContent?.trim()) {
        setStatus("You cannot connect to yourself", "error");
        return;
    }

    if (conn?.open) {
        setStatus("Already connected", "connected");
        return;
    }

    try {
        setStatus("Connecting...", "connecting");

        localKeyPair = await generateKeyPair();
        sharedAESKey = null;

        const connection = peer.connect(targetPeerId, {
            reliable: true,
            serialization: "json",
        });

        setupConnection(connection);
    } catch (error) {
        console.error("Connection failed:", error);
        setStatus("Connection failed", "error");
    }
}

async function initPeer() {
    try {
        setStatus("Getting connection servers...", "connecting");

        const iceServers = await getIceServers();

        localKeyPair = await generateKeyPair();

        peer = new Peer(generateShortCode(), {
            debug: 1,
            config: {
                iceServers,
                iceTransportPolicy: "all",
                iceCandidatePoolSize: 2,
            },
        });

        peer.on("open", id => {
            if (myPeerIdEl) {
                myPeerIdEl.textContent = id;
            }

            setStatus("Ready to connect", "connected");
        });

        peer.on("connection", connection => {
            setupConnection(connection);
        });

        peer.on("error", error => {
            console.error("PeerJS error:", error);

            clearConnectionTimer();

            let message = "Connection error";

            if (error?.type === "peer-unavailable") {
                message = "Peer not found";
            } else if (error?.type === "network") {
                message = "Network error";
            } else if (error?.type === "server-error") {
                message = "Signaling server error";
            }

            setStatus(message, "error");
        });

        peer.on("disconnected", () => {
            setStatus("Disconnected from signaling server", "error");

            if (!peer.destroyed) {
                peer.reconnect();
            }
        });

        peer.on("close", () => {
            setStatus("Peer closed", "error");
        });
    } catch (error) {
        console.error("Peer initialization failed:", error);
        setStatus("Unable to initialize connection", "error");
    }
}

async function handleFileSelection(event) {
    const file = event.target.files?.[0];

    if (!file) {
        return;
    }

    if (!conn || !conn.open) {
        setStatus("Connect to a peer first", "error");
        event.target.value = "";
        return;
    }

    if (!sharedAESKey) {
        setStatus("Secure connection is not ready", "error");
        event.target.value = "";
        return;
    }

    if (file.size > MAX_FILE_SIZE) {
        updateUploadStatus(
            `Maximum file size is ${formatBytes(MAX_FILE_SIZE)}`
        );

        event.target.value = "";
        return;
    }

    if (fileNameEl) {
        fileNameEl.textContent = file.name;
    }

    if (fileSizeEl) {
        fileSizeEl.textContent = formatBytes(file.size);
    }

    try {
        await sendFile(file);
    } catch (error) {
        console.error("File transfer failed:", error);
        updateUploadStatus(error.message || "File transfer failed");
        setStatus("File transfer failed", "error");
        transferInProgress = false;
    } finally {
        event.target.value = "";
    }
}

async function copyPeerId() {
    const id = myPeerIdEl?.textContent?.trim();

    if (!id) {
        return;
    }

    try {
        await navigator.clipboard.writeText(id);

        const originalText = copyIdBtn?.textContent;

        if (copyIdBtn) {
            copyIdBtn.textContent = "Copied";
        }

        setTimeout(() => {
            if (copyIdBtn) {
                copyIdBtn.textContent = originalText || "Copy";
            }
        }, 1500);
    } catch (error) {
        console.error("Copy failed:", error);
    }
}

function setupTabs() {
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const target = tab.dataset.tab;

            tabs.forEach(item => {
                item.classList.toggle(
                    "active",
                    item.dataset.tab === target
                );
            });

            tabViews.forEach(view => {
                view.classList.toggle(
                    "active",
                    view.dataset.view === target
                );
            });
        });
    });
}

if (connectBtn) {
    connectBtn.addEventListener("click", connectToPeer);
}

if (copyIdBtn) {
    copyIdBtn.addEventListener("click", copyPeerId);
}

if (fileInput) {
    fileInput.addEventListener("change", handleFileSelection);
}

if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener("click", () => {
        localStorage.removeItem("zeroshare_history");
        renderHistory();
    });
}

if (targetPeerIdEl) {
    targetPeerIdEl.addEventListener("keydown", event => {
        if (event.key === "Enter") {
            connectToPeer();
        }
    });
}

setupTabs();
renderHistory();
showSetupSection();
initPeer();