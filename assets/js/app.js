const myPeerIdEl = document.getElementById("myPeerId");
const targetPeerIdInput = document.getElementById("targetPeerId");
const connectBtn = document.getElementById("connectBtn");
const copyIdBtn = document.getElementById("copyIdBtn");
const connectionStatus = document.getElementById("connectionStatus");
const statusDot = connectionStatus?.querySelector(".dot");

const setupSection = document.getElementById("setupSection");
const transferSection = document.getElementById("transferSection");

const fileInput = document.getElementById("fileInput");
const progressContainer = document.getElementById("progressContainer");
const progressBar = document.getElementById("progressBar");
const transferPercent = document.getElementById("transferPercent");
const transferLabel = document.getElementById("transferLabel");

const receivedFilesDiv = document.getElementById("receivedFiles");

const tabApp = document.getElementById("tabApp");
const tabHistory = document.getElementById("tabHistory");
const appView = document.getElementById("appView");
const historyView = document.getElementById("historyView");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const CHUNK_SIZE = 16 * 1024; 
const CONNECTION_TIMEOUT = 15000;
const MAX_HISTORY_ITEMS = 100;
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024; 
let peer = null;
let conn = null;
let localKeyPair = null;
let sharedAESKey = null;
let receiveBuffer = [];
let incomingMeta = null;
let receivedBytes = 0;

let connectionTimer = null;
let transferCancelled = false;
function saveHistory(action, details) {
    try {
        const history = JSON.parse(
            localStorage.getItem("zeroShareHistory") || "[]"
        );

        history.unshift({
            action,
            details,
            time: new Date().toLocaleString()
        });

        if (history.length > MAX_HISTORY_ITEMS) {
            history.length = MAX_HISTORY_ITEMS;
        }

        localStorage.setItem(
            "zeroShareHistory",
            JSON.stringify(history)
        );

        renderHistory();

    } catch (error) {
        console.error("History error:", error);
    }
}


function renderHistory() {
    if (!historyList) return;

    try {
        const history = JSON.parse(
            localStorage.getItem("zeroShareHistory") || "[]"
        );

        historyList.replaceChildren();

        if (!history.length) {
            const empty = document.createElement("div");

            empty.style.cssText =
                "color:var(--text-muted);text-align:center;padding:1rem;";

            empty.textContent = "No history found.";

            historyList.appendChild(empty);

            return;
        }

        history.forEach(item => {
            const container = document.createElement("div");
            container.className = "history-item";

            const action = document.createElement("span");
            action.className = "history-action";
            action.textContent = item.action;

            const details = document.createElement("span");
            details.textContent = item.details;

            const time = document.createElement("span");
            time.className = "history-time";
            time.textContent = item.time;

            container.append(
                action,
                details,
                time
            );

            historyList.appendChild(container);
        });

    } catch (error) {
        console.error("Unable to render history:", error);
    }
}


if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener("click", () => {
        localStorage.removeItem("zeroShareHistory");
        renderHistory();
    });
}

if (tabApp && tabHistory) {

    tabApp.addEventListener("click", () => {
        tabApp.classList.add("active");
        tabHistory.classList.remove("active");

        appView.style.display = "block";
        historyView.style.display = "none";
    });


    tabHistory.addEventListener("click", () => {
        tabHistory.classList.add("active");
        tabApp.classList.remove("active");

        appView.style.display = "none";
        historyView.style.display = "block";

        renderHistory();
    });
}

async function initCrypto() {

    localKeyPair = await crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        false,
        ["deriveKey"]
    );
}


async function exportPublicKey() {
    return crypto.subtle.exportKey(
        "jwk",
        localKeyPair.publicKey
    );
}


async function deriveAESKey(peerJwk) {

    if (!peerJwk || peerJwk.kty !== "EC") {
        throw new Error("Invalid peer public key.");
    }

    const peerPubKey = await crypto.subtle.importKey(
        "jwk",
        peerJwk,
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        false,
        []
    );

    return crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: peerPubKey
        },
        localKeyPair.privateKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}


function generateShortCode() {

    const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    const randomValues =
        new Uint32Array(8);

    crypto.getRandomValues(randomValues);

    let result = "";

    for (let i = 0; i < randomValues.length; i++) {
        result +=
            chars[randomValues[i] % chars.length];
    }

    return result;
}


async function getIceServers() {

    const response = await fetch(
        "/api/turn-credentials",
        {
            method: "GET",
            headers: {
                "Accept": "application/json"
            },
            cache: "no-store"
        }
    );

    if (!response.ok) {
        throw new Error(
            `TURN configuration failed (${response.status})`
        );
    }

    const data = await response.json();

    if (
        !data ||
        !Array.isArray(data.iceServers) ||
        data.iceServers.length === 0
    ) {
        throw new Error(
            "No ICE servers were returned."
        );
    }

    return data.iceServers;
}

async function initPeer() {

    try {

        updateStatus(false, "Loading...");

        await initCrypto();

        const iceServers = await getIceServers();

        const shortId = generateShortCode();

        const peerConfig = {
            debug: 1,

            config: {
                iceServers,
                iceTransportPolicy: "all"
            }
        };

        peer = new Peer(shortId, peerConfig);


        peer.on("open", id => {

            if (myPeerIdEl) {
                myPeerIdEl.textContent = id;
            }

            updateStatus(false, "Waiting...");

            renderHistory();
        });


        peer.on("disconnected", () => {

            if (!peer.destroyed) {
                updateStatus(false, "Reconnecting...");
                peer.reconnect();
            }
        });


        peer.on("connection", incomingConnection => {

            if (conn && conn.open) {
                incomingConnection.close();
                return;
            }

            conn = incomingConnection;

            setupConnectionHandlers();
        });


        peer.on("error", error => {

            console.error("PeerJS error:", error);

            clearTimeout(connectionTimer);

            if (connectBtn) {
                connectBtn.textContent = "Connect";
                connectBtn.disabled = false;
            }

            updateStatus(false, "Connection error");

            saveHistory(
                "Connection Error",
                error?.type || "Unknown error"
            );
        });


        peer.on("close", () => {

            updateStatus(false, "Offline");
        });


    } catch (error) {

        console.error(
            "Peer initialization failed:",
            error
        );

        updateStatus(
            false,
            "TURN configuration failed"
        );

        if (connectBtn) {
            connectBtn.textContent = "Retry";
            connectBtn.disabled = false;
        }
    }
}

function setupConnectionHandlers() {

    if (!conn) return;

    conn.on("open", async () => {

        try {

            clearTimeout(connectionTimer);

            updateStatus(true);

            if (connectBtn) {
                connectBtn.textContent = "Connected";
            }

            saveHistory(
                "Connected",
                `Established secure tunnel with Peer ID: ${conn.peer}`
            );

            const exportedPubKey =
                await exportPublicKey();

            conn.send({
                type: "PUB_KEY",
                key: exportedPubKey
            });

        } catch (error) {

            console.error(
                "Connection setup error:",
                error
            );

            closeConnection();
        }
    });


    conn.on("data", async message => {

        try {

            if (!message || typeof message !== "object") {
                return;
            }

            if (message.type === "PUB_KEY") {

                sharedAESKey =
                    await deriveAESKey(message.key);

                showTransferUI();

                return;
            }

            if (message.type === "META") {

                if (!sharedAESKey) {
                    throw new Error(
                        "Secure key not established."
                    );
                }

                const decryptedMeta =
                    await decryptJSON(
                        message.iv,
                        message.data
                    );

                validateMetadata(decryptedMeta);

                incomingMeta = decryptedMeta;

                receiveBuffer = [];
                receivedBytes = 0;

                transferCancelled = false;

                progressContainer.style.display =
                    "block";

                transferLabel.textContent =
                    `Receiving: ${incomingMeta.name}`;

                updateProgress(
                    0,
                    incomingMeta.size
                );

                return;
            }

            if (message.type === "CHUNK") {

                if (
                    !sharedAESKey ||
                    !incomingMeta
                ) {
                    throw new Error(
                        "Invalid transfer state."
                    );
                }

                const decryptedBuffer =
                    await decryptBuffer(
                        message.iv,
                        message.data
                    );

                if (
                    decryptedBuffer.byteLength !==
                    message.originalSize
                ) {
                    throw new Error(
                        "Chunk size verification failed."
                    );
                }

                receiveBuffer.push(
                    decryptedBuffer
                );

                receivedBytes +=
                    decryptedBuffer.byteLength;

                if (
                    receivedBytes >
                    incomingMeta.size
                ) {
                    throw new Error(
                        "Received more data than expected."
                    );
                }

                updateProgress(
                    receivedBytes,
                    incomingMeta.size
                );

                return;
            }

            if (message.type === "EOF") {

                if (
                    !incomingMeta ||
                    !sharedAESKey
                ) {
                    throw new Error(
                        "Invalid transfer completion."
                    );
                }

                if (
                    receivedBytes !==
                    incomingMeta.size
                ) {
                    throw new Error(
                        "File size verification failed."
                    );
                }

                transferLabel.textContent =
                    "Preparing file...";

                const blob = new Blob(
                    receiveBuffer,
                    {
                        type:
                            incomingMeta.fileType ||
                            "application/octet-stream"
                    }
                );

                createDownloadableFile(
                    blob,
                    incomingMeta.name
                );

                saveHistory(
                    "Received File",
                    `Name: ${incomingMeta.name}, Size: ${formatBytes(incomingMeta.size)}`
                );

                transferLabel.textContent =
                    "Complete!";

                progressBar.style.background =
                    "#10b981";

                setTimeout(() => {

                    progressContainer.style.display =
                        "none";

                }, 3000);

                cleanupTransfer();

                return;
            }


            if (message.type === "ERROR") {

                throw new Error(
                    message.message ||
                    "Remote transfer error."
                );
            }

        } catch (error) {

            console.error(
                "Incoming data error:",
                error
            );

            transferLabel.textContent =
                "Transfer failed.";

            saveHistory(
                "Transfer Error",
                error.message
            );

            cleanupTransfer();
        }
    });


    conn.on("close", () => {

        clearTimeout(connectionTimer);

        updateStatus(false);

        cleanupTransfer();

        if (connectBtn) {
            connectBtn.textContent = "Connect";
            connectBtn.disabled = false;
        }

    });


    conn.on("error", error => {

        console.error(
            "Data connection error:",
            error
        );

        updateStatus(
            false,
            "Connection error"
        );
    });
}

async function encryptBuffer(buffer) {

    const iv =
        crypto.getRandomValues(
            new Uint8Array(12)
        );

    const encrypted =
        await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv
            },
            sharedAESKey,
            buffer
        );

    return {
        iv: Array.from(iv),
        data: encrypted
    };
}


async function decryptBuffer(ivArray, encryptedData) {

    if (
        !Array.isArray(ivArray) ||
        ivArray.length !== 12
    ) {
        throw new Error(
            "Invalid encryption IV."
        );
    }

    const iv =
        new Uint8Array(ivArray);

    return crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv
        },
        sharedAESKey,
        encryptedData
    );
}


async function encryptJSON(object) {

    const encoded =
        new TextEncoder().encode(
            JSON.stringify(object)
        );

    return encryptBuffer(encoded);
}


async function decryptJSON(iv, encryptedData) {

    const decrypted =
        await decryptBuffer(
            iv,
            encryptedData
        );

    const text =
        new TextDecoder().decode(
            decrypted
        );

    return JSON.parse(text);
}



function validateMetadata(meta) {

    if (!meta || typeof meta !== "object") {
        throw new Error(
            "Invalid file metadata."
        );
    }

    if (
        typeof meta.name !== "string" ||
        !meta.name ||
        meta.name.length > 255
    ) {
        throw new Error(
            "Invalid filename."
        );
    }

    if (
        !Number.isSafeInteger(meta.size) ||
        meta.size < 0 ||
        meta.size > MAX_FILE_SIZE
    ) {
        throw new Error(
            "Invalid file size."
        );
    }

    if (
        typeof meta.fileType !== "string" ||
        meta.fileType.length > 255
    ) {
        throw new Error(
            "Invalid file type."
        );
    }
}

if (fileInput) {

    fileInput.addEventListener(
        "change",
        async event => {

            const file =
                event.target.files?.[0];

            if (!file) return;

            if (!sharedAESKey || !conn || !conn.open) {

                alert(
                    "Please establish a secure connection first."
                );

                fileInput.value = "";
                return;
            }

            if (file.size > MAX_FILE_SIZE) {

                alert(
                    "This file is too large."
                );

                fileInput.value = "";
                return;
            }

            try {

                transferCancelled = false;

                progressContainer.style.display =
                    "block";

                transferLabel.textContent =
                    `Preparing: ${file.name}`;

                progressBar.style.background =
                    "var(--gradient-brand)";

                const metadata = {

                    name: file.name,

                    size: file.size,

                    fileType:
                        file.type ||
                        "application/octet-stream"
                };

                const encryptedMeta =
                    await encryptJSON(metadata);

                conn.send({
                    type: "META",
                    iv: encryptedMeta.iv,
                    data: encryptedMeta.data
                });


                /* =========================================
                   FILE CHUNKS
                ========================================= */

                let offset = 0;

                while (
                    offset < file.size
                ) {

                    if (
                        !conn ||
                        !conn.open
                    ) {
                        throw new Error(
                            "Connection closed during transfer."
                        );
                    }

                    const chunk =
                        file.slice(
                            offset,
                            Math.min(
                                offset + CHUNK_SIZE,
                                file.size
                            )
                        );

                    const arrayBuffer =
                        await chunk.arrayBuffer();

                    const encrypted =
                        await encryptBuffer(
                            arrayBuffer
                        );

                    conn.send({
                        type: "CHUNK",

                        iv: encrypted.iv,

                        data: encrypted.data,

                        originalSize:
                            arrayBuffer.byteLength
                    });

                    offset +=
                        arrayBuffer.byteLength;

                    updateProgress(
                        offset,
                        file.size
                    );

                    /*
                     * Small yield prevents the browser
                     * event loop from being monopolized.
                     */
                    await sleep(4);
                }


                /* =========================================
                   END OF FILE
                ========================================= */

                conn.send({
                    type: "EOF"
                });

                saveHistory(
                    "Sent File",
                    `Name: ${file.name}, Size: ${formatBytes(file.size)}`
                );

                transferLabel.textContent =
                    "Sent successfully!";

                progressBar.style.background =
                    "#10b981";

                fileInput.value = "";


            } catch (error) {

                console.error(
                    "File transfer failed:",
                    error
                );

                transferLabel.textContent =
                    "Transfer failed.";

                saveHistory(
                    "Transfer Error",
                    error.message
                );

                fileInput.value = "";
            }
        }
    );
}


/* =========================================================
   CONNECT BUTTON
========================================================= */

if (connectBtn) {

    connectBtn.addEventListener(
        "click",
        () => {

            if (!peer || peer.destroyed) {

                alert(
                    "Peer connection is not ready."
                );

                return;
            }

            const targetId =
                targetPeerIdInput
                    ?.value
                    ?.trim()
                    ?.toUpperCase();

            if (!targetId) {
                return;
            }

            if (
                myPeerIdEl &&
                targetId ===
                myPeerIdEl.textContent
            ) {

                alert(
                    "You cannot connect to yourself."
                );

                return;
            }

            if (conn && conn.open) {

                alert(
                    "You are already connected."
                );

                return;
            }


            connectBtn.textContent =
                "Connecting...";

            connectBtn.disabled = true;

            updateStatus(
                false,
                "Connecting..."
            );


            try {

                conn = peer.connect(
                    targetId,
                    {
                        reliable: true
                    }
                );

                setupConnectionHandlers();


                clearTimeout(
                    connectionTimer
                );

                connectionTimer =
                    setTimeout(() => {

                        if (
                            !conn ||
                            !conn.open
                        ) {

                            if (conn) {
                                conn.close();
                            }

                            updateStatus(
                                false,
                                "Connection timeout"
                            );

                            connectBtn.textContent =
                                "Connect";

                            connectBtn.disabled =
                                false;
                        }

                    }, CONNECTION_TIMEOUT);


            } catch (error) {

                console.error(
                    "Connection failed:",
                    error
                );

                connectBtn.textContent =
                    "Connect";

                connectBtn.disabled =
                    false;
            }
        }
    );
}


/* =========================================================
   COPY PEER ID
========================================================= */

if (copyIdBtn) {

    copyIdBtn.addEventListener(
        "click",
        async () => {

            const peerId =
                myPeerIdEl?.textContent?.trim();

            if (!peerId) return;

            try {

                await navigator.clipboard.writeText(
                    peerId
                );

                const originalIcon =
                    copyIdBtn.innerHTML;

                copyIdBtn.innerHTML =
                    '<i data-lucide="check" style="color:#10b981;"></i>';

                if (window.lucide) {
                    lucide.createIcons();
                }

                setTimeout(() => {

                    copyIdBtn.innerHTML =
                        originalIcon;

                    if (window.lucide) {
                        lucide.createIcons();
                    }

                }, 2000);

            } catch (error) {

                console.error(
                    "Clipboard error:",
                    error
                );
            }
        }
    );
}


/* =========================================================
   UI STATUS
========================================================= */

function updateStatus(
    isConnected,
    customText = null
) {

    if (!statusDot) return;

    if (isConnected) {

        statusDot.className =
            "dot connected";

    } else {

        statusDot.className =
            "dot disconnected";
    }

    if (connectionStatus) {

        /*
         * Preserve the dot and only update text nodes.
         */
        const textNode =
            Array.from(
                connectionStatus.childNodes
            ).find(
                node =>
                    node.nodeType ===
                    Node.TEXT_NODE
            );

        if (textNode) {

            textNode.textContent =
                ` ${customText ||
                    (isConnected
                        ? "Connected"
                        : "Waiting...")}`;
        }
    }
}


/* =========================================================
   TRANSFER UI
========================================================= */

function showTransferUI() {

    if (setupSection) {
        setupSection.style.display =
            "none";
    }

    if (transferSection) {
        transferSection.style.display =
            "block";
    }
}


function updateProgress(
    current,
    total
) {

    const percent =
        total === 0
            ? 100
            : Math.min(
                Math.round(
                    (current / total) * 100
                ),
                100
            );

    if (progressBar) {
        progressBar.style.width =
            `${percent}%`;
    }

    if (transferPercent) {
        transferPercent.textContent =
            `${percent}%`;
    }
}


/* =========================================================
   DOWNLOAD
========================================================= */

function createDownloadableFile(
    blob,
    filename
) {

    const url =
        URL.createObjectURL(blob);

    const fileItem =
        document.createElement("div");

    fileItem.className =
        "received-item";

    const link =
        document.createElement("a");

    link.href = url;
    link.download = filename;

    const icon =
        document.createElement("i");

    icon.setAttribute(
        "data-lucide",
        "file-check"
    );

    link.appendChild(icon);

    /*
     * Never insert the filename through
     * innerHTML.
     */
    link.appendChild(
        document.createTextNode(
            ` ${filename}`
        )
    );

    fileItem.appendChild(link);

    receivedFilesDiv?.appendChild(
        fileItem
    );

    if (window.lucide) {
        lucide.createIcons();
    }

    /*
     * Keep the object URL alive until
     * the user has had time to download.
     */
    setTimeout(() => {

        URL.revokeObjectURL(url);

    }, 10 * 60 * 1000);
}


/* =========================================================
   CLEANUP
========================================================= */

function cleanupTransfer() {

    receiveBuffer = [];
    incomingMeta = null;
    receivedBytes = 0;
    transferCancelled = false;
}


function closeConnection() {

    clearTimeout(connectionTimer);

    try {
        conn?.close();
    } catch {}

    conn = null;
    sharedAESKey = null;

    cleanupTransfer();

    updateStatus(false);

    if (connectBtn) {

        connectBtn.textContent =
            "Connect";

        connectBtn.disabled =
            false;
    }
}


/* =========================================================
   UTILITIES
========================================================= */

function sleep(ms) {

    return new Promise(
        resolve => setTimeout(resolve, ms)
    );
}


function formatBytes(bytes) {

    if (bytes === 0) {
        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    ];

    const index =
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        );

    return `${(
        bytes /
        Math.pow(1024, index)
    ).toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}


/* =========================================================
   START APPLICATION
========================================================= */

renderHistory();

if (myPeerIdEl) {
    initPeer();
}
