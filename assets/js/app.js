const CHUNK_SIZE = 8 * 1024;
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;
const HISTORY_KEY = "zeroshare_history";

const myPeerId = document.getElementById("myPeerId");
const targetPeerId = document.getElementById("targetPeerId");
const connectBtn = document.getElementById("connectBtn");
const copyIdBtn = document.getElementById("copyIdBtn");
const connectionStatus = document.getElementById("connectionStatus");

const setupSection = document.getElementById("setupSection");
const transferSection = document.getElementById("transferSection");

const fileInput = document.getElementById("fileInput");
const transferActivity = document.getElementById("transferActivity");
const connectedPeerId = document.getElementById("connectedPeerId");

const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

const tabApp = document.getElementById("tabApp");
const tabHistory = document.getElementById("tabHistory");

const appView = document.getElementById("appView");
const historyView = document.getElementById("historyView");

let peer = null;
let conn = null;

let localKeyPair = null;
let sharedAESKey = null;

let incomingMeta = null;
let receiveBuffer = [];
let receivedBytes = 0;
let incomingChunks = 0;

let activeSendTransfer = null;
let activeReceiveTransfer = null;

let receiveStartTime = 0;
let connectionTimer = null;
let transferInProgress = false;


function generateShortCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let result = "";

  for (let i = 0; i < 8; i++) {
    result += chars.charAt(
      Math.floor(Math.random() * chars.length)
    );
  }

  return result;
}


function formatTransferSize(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}


function escapeHTML(value) {
  const div = document.createElement("div");
  div.textContent = String(value);
  return div.innerHTML;
}


function updateConnectionStatus(text, connected = false) {
  if (!connectionStatus) {
    return;
  }

  const dotClass = connected
    ? "connected"
    : "disconnected";

  connectionStatus.innerHTML = `
    <span class="dot ${dotClass}"></span>
    ${escapeHTML(text)}
  `;
}


function showSetupSection() {
  setupSection.style.display = "block";
  transferSection.style.display = "none";
}


function showTransferSection() {
  setupSection.style.display = "none";
  transferSection.style.display = "block";
}


function switchView(view) {
  if (view === "history") {
    appView.style.display = "none";
    historyView.style.display = "block";

    tabApp.classList.remove("active");
    tabHistory.classList.add("active");

    renderHistory();
  } else {
    historyView.style.display = "none";
    appView.style.display = "block";

    tabHistory.classList.remove("active");
    tabApp.classList.add("active");
  }
}


function setupTabs() {
  tabApp.addEventListener("click", () => {
    switchView("app");
  });

  tabHistory.addEventListener("click", () => {
    switchView("history");
  });
}


async function getIceServers() {
  const response = await fetch(
    "/api/turn-credentials",
    {
      method: "GET",
      cache: "no-store"
    }
  );

  if (!response.ok) {
    let message = "Unable to obtain ICE servers.";

    try {
      const errorData = await response.json();

      if (errorData?.error) {
        message = errorData.error;
      }
    } catch {
    }

    throw new Error(message);
  }

  const data = await response.json();

  if (
    !data ||
    !Array.isArray(data.iceServers) ||
    data.iceServers.length === 0
  ) {
    throw new Error("No ICE servers were returned.");
  }

  return data.iceServers;
}


async function initPeer() {
  try {
    updateConnectionStatus("Connecting...");

    const iceServers = await getIceServers();

    peer = new Peer(
      generateShortCode(),
      {
        debug: 1,
        config: {
          iceServers,
          iceTransportPolicy: "all",
          iceCandidatePoolSize: 2
        }
      }
    );

    peer.on("open", id => {
      myPeerId.textContent = id;
      updateConnectionStatus("Waiting...");
    });

    peer.on("connection", incomingConnection => {
      if (conn && conn.open) {
        incomingConnection.close();
        return;
      }

      setupConnection(incomingConnection);
    });

    peer.on("error", error => {
      console.error("PeerJS error:", error);

      if (error.type === "peer-unavailable") {
        updateConnectionStatus("Peer not found");
      } else if (error.type === "network") {
        updateConnectionStatus("Network error");
      } else {
        updateConnectionStatus("Connection error");
      }
    });

    peer.on("disconnected", () => {
      updateConnectionStatus("Disconnected");

      if (!conn || !conn.open) {
        showSetupSection();
      }
    });

    peer.on("close", () => {
      updateConnectionStatus("Closed");
      showSetupSection();
    });

  } catch (error) {
    console.error("Peer initialization failed:", error);

    updateConnectionStatus("Connection unavailable");

    setTimeout(() => {
      initPeer();
    }, 5000);
  }
}


function connectToPeer() {
  const targetId = targetPeerId.value.trim();

  if (!targetId) {
    targetPeerId.focus();
    return;
  }

  if (!peer || peer.destroyed) {
    updateConnectionStatus("Not ready");
    return;
  }

  if (targetId === peer.id) {
    updateConnectionStatus("Cannot connect to yourself");
    return;
  }

  connectBtn.disabled = true;
  updateConnectionStatus("Connecting...");

  const newConnection = peer.connect(
    targetId,
    {
      reliable: true,
      serialization: "raw"
    }
  );

  setupConnection(newConnection);
}


function setupConnection(connection) {
  if (conn && conn !== connection) {
    try {
      conn.close();
    } catch {
    }
  }

  conn = connection;

  conn.on("open", async () => {
    updateConnectionStatus("Connected", true);

    connectedPeerId.textContent =
      conn.peer || "Peer";

    showTransferSection();

    connectBtn.disabled = false;

    clearTimeout(connectionTimer);

    try {
      await createLocalKeyPair();
      await sendPublicKey();
    } catch (error) {
      console.error(
        "Key exchange initialization failed:",
        error
      );

      updateConnectionStatus("Security setup failed");
    }
  });

  conn.on("data", async data => {
    try {
      await handleIncomingData(data);
    } catch (error) {
      console.error(
        "Incoming data error:",
        error
      );

      if (activeReceiveTransfer) {
        activeReceiveTransfer.label.textContent =
          "Transfer failed";

        activeReceiveTransfer.speed.textContent =
          error.message || "Unable to receive file.";
      }
    }
  });

  conn.on("close", () => {
    if (conn === connection) {
      conn = null;
    }

    sharedAESKey = null;

    updateConnectionStatus("Disconnected");

    connectedPeerId.textContent = "Peer";

    showSetupSection();
  });

  conn.on("error", error => {
    console.error(
      "Data connection error:",
      error
    );

    updateConnectionStatus("Connection error");
  });
}


async function createLocalKeyPair() {
  localKeyPair = await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true,
    [
      "deriveKey",
      "deriveBits"
    ]
  );
}


async function exportPublicKey() {
  const key = await crypto.subtle.exportKey(
    "raw",
    localKeyPair.publicKey
  );

  return arrayBufferToBase64(key);
}


async function importPublicKey(base64Key) {
  const rawKey = base64ToArrayBuffer(base64Key);

  return crypto.subtle.importKey(
    "raw",
    rawKey,
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    false,
    []
  );
}


async function sendPublicKey() {
  if (!conn || !conn.open || !localKeyPair) {
    return;
  }

  const publicKey = await exportPublicKey();

  conn.send(
    JSON.stringify({
      type: "KEY",
      key: publicKey
    })
  );
}


async function deriveSharedKey(remotePublicKey) {
  sharedAESKey = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: remotePublicKey
    },
    localKeyPair.privateKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    [
      "encrypt",
      "decrypt"
    ]
  );
}


async function encryptBinary(buffer) {
  if (!sharedAESKey) {
    throw new Error("Secure key is not available.");
  }

  const iv = crypto.getRandomValues(
    new Uint8Array(12)
  );

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    sharedAESKey,
    buffer
  );

  const result = new Uint8Array(
    iv.byteLength + encrypted.byteLength
  );

  result.set(iv, 0);
  result.set(
    new Uint8Array(encrypted),
    iv.byteLength
  );

  return result.buffer;
}


async function decryptBinary(buffer) {
  if (!sharedAESKey) {
    throw new Error("Secure key is not available.");
  }

  const bytes = new Uint8Array(buffer);

  if (bytes.byteLength < 28) {
    throw new Error("Invalid encrypted chunk.");
  }

  const iv = bytes.slice(0, 12);
  const encrypted = bytes.slice(12);

  return crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv
    },
    sharedAESKey,
    encrypted
  );
}


async function encryptJSON(data) {
  const text = JSON.stringify(data);
  const encoded = new TextEncoder().encode(text);

  const encrypted = await encryptBinary(
    encoded.buffer
  );

  return arrayBufferToBase64(encrypted);
}


async function decryptJSON(data) {
  const encrypted = base64ToArrayBuffer(data);

  const decrypted = await decryptBinary(
    encrypted
  );

  const text = new TextDecoder().decode(
    decrypted
  );

  return JSON.parse(text);
}


function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);

  let binary = "";

  const chunkSize = 0x8000;

  for (
    let i = 0;
    i < bytes.length;
    i += chunkSize
  ) {
    binary += String.fromCharCode(
      ...bytes.subarray(
        i,
        Math.min(i + chunkSize, bytes.length)
      )
    );
  }

  return btoa(binary);
}


function base64ToArrayBuffer(base64) {
  const binary = atob(base64);

  const bytes = new Uint8Array(
    binary.length
  );

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}


function createTransferCard(type, metadata) {
  const card = document.createElement("div");

  card.className = "transfer-card";

  const label =
    type === "send"
      ? "Sending"
      : "Receiving";

  const icon =
    type === "send"
      ? "upload"
      : "download";

  card.innerHTML = `
    <div class="transfer-card-header">

      <div class="transfer-file-icon">
        <i data-lucide="file"></i>
      </div>

      <div class="transfer-file-info">

        <span
          class="transfer-file-name"
          title="${escapeHTML(metadata.name)}"
        >
          ${escapeHTML(metadata.name)}
        </span>

        <span class="transfer-file-meta">
          ${formatTransferSize(metadata.size)}
        </span>

      </div>

      <div class="transfer-status">

        <i data-lucide="${icon}"></i>

        <span>
          ${label}
        </span>

      </div>

    </div>

    <div class="transfer-progress">

      <div class="transfer-progress-info">

        <span class="transfer-progress-label">
          Preparing...
        </span>

        <span class="transfer-progress-percent">
          0%
        </span>

      </div>

      <div class="transfer-progress-bg">

        <div class="transfer-progress-fill"></div>

      </div>

      <div class="transfer-speed"></div>

    </div>
  `;

  transferActivity.prepend(card);

  if (window.lucide) {
    lucide.createIcons();
  }

  return {
    card,
    fill: card.querySelector(
      ".transfer-progress-fill"
    ),
    percent: card.querySelector(
      ".transfer-progress-percent"
    ),
    label: card.querySelector(
      ".transfer-progress-label"
    ),
    status: card.querySelector(
      ".transfer-status"
    ),
    speed: card.querySelector(
      ".transfer-speed"
    )
  };
}


function updateTransferCard(
  transfer,
  loaded,
  total,
  label
) {
  if (!transfer) {
    return;
  }

  const percent =
    total > 0
      ? Math.min(
          100,
          Math.round(
            (loaded / total) * 100
          )
        )
      : 0;

  transfer.fill.style.width =
    `${percent}%`;

  transfer.percent.textContent =
    `${percent}%`;

  transfer.label.textContent =
    label;
}


function completeTransferCard(
  transfer,
  type
) {
  if (!transfer) {
    return;
  }

  transfer.fill.style.width = "100%";
  transfer.percent.textContent = "100%";
  transfer.label.textContent =
    "Transfer complete";

  transfer.card.classList.add(
    "transfer-complete"
  );

  transfer.status.innerHTML = `
    <i data-lucide="check-circle-2"></i>
    <span>
      ${type === "send" ? "Sent" : "Received"}
    </span>
  `;

  if (window.lucide) {
    lucide.createIcons();
  }
}


function addDownloadToTransfer(
  transfer,
  blob,
  filename
) {
  if (!transfer) {
    return;
  }

  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");

  link.className = "transfer-download";

  link.href = url;
  link.download = filename;

  link.innerHTML = `
    <i data-lucide="download"></i>
    Download file
  `;

  transfer.card.appendChild(link);

  if (window.lucide) {
    lucide.createIcons();
  }
}


async function sendFile(file) {
  if (!file) {
    return;
  }

  if (!conn || !conn.open) {
    alert("Not connected to a peer.");
    return;
  }

  if (!sharedAESKey) {
    alert(
      "Secure connection is not ready."
    );
    return;
  }

  if (file.size > MAX_FILE_SIZE) {
    alert(
      `File is too large. Maximum size is ${formatTransferSize(MAX_FILE_SIZE)}.`
    );
    return;
  }

  if (transferInProgress) {
    alert(
      "A file transfer is already in progress."
    );
    return;
  }

  transferInProgress = true;

  const metadata = {
    name: file.name,
    size: file.size,
    fileType:
      file.type ||
      "application/octet-stream"
  };

  const transfer =
    createTransferCard(
      "send",
      metadata
    );

  activeSendTransfer = transfer;

  try {
    const encryptedMeta =
      await encryptJSON(metadata);

    conn.send(
      JSON.stringify({
        type: "META",
        data: encryptedMeta
      })
    );

    let offset = 0;

    const startedAt =
      performance.now();

    updateTransferCard(
      transfer,
      0,
      file.size,
      "Sending..."
    );

    while (offset < file.size) {
      if (!conn || !conn.open) {
        throw new Error(
          "Connection closed during transfer."
        );
      }

      const chunk =
        await file
          .slice(
            offset,
            offset + CHUNK_SIZE
          )
          .arrayBuffer();

      const encryptedChunk =
        await encryptBinary(chunk);

      conn.send(encryptedChunk);

      offset += chunk.byteLength;

      const elapsed =
        (performance.now() - startedAt) /
        1000;

      const speed =
        elapsed > 0
          ? offset / elapsed
          : 0;

      updateTransferCard(
        transfer,
        offset,
        file.size,
        "Sending..."
      );

      transfer.speed.textContent =
        `${formatTransferSize(speed)}/s`;
    }

    conn.send(
      JSON.stringify({
        type: "END"
      })
    );

    completeTransferCard(
      transfer,
      "send"
    );

    saveHistory({
      type: "sent",
      name: file.name,
      size: file.size,
      timestamp: Date.now()
    });

  } catch (error) {
    console.error(
      "File sending failed:",
      error
    );

    transfer.label.textContent =
      "Transfer failed";

    transfer.status.innerHTML = `
      <i data-lucide="circle-x"></i>
      <span>Failed</span>
    `;

    transfer.speed.textContent =
      error.message ||
      "Unable to send file.";

    if (window.lucide) {
      lucide.createIcons();
    }

  } finally {
    transferInProgress = false;
    activeSendTransfer = null;
    fileInput.value = "";
  }
}


async function handleIncomingData(data) {
  if (typeof data === "string") {
    const message = JSON.parse(data);

    switch (message.type) {
      case "KEY":
        await handleKeyMessage(message);
        break;

      case "KEY_ACK":
        await handleKeyAck();
        break;

      case "META":
        await handleMetaMessage(
          message.data
        );
        break;

      case "END":
        await handleEndMessage();
        break;

      default:
        console.warn(
          "Unknown message type:",
          message.type
        );
    }

    return;
  }

  if (data instanceof ArrayBuffer) {
    await handleBinaryChunk(data);
    return;
  }

  if (ArrayBuffer.isView(data)) {
    await handleBinaryChunk(
      data.buffer.slice(
        data.byteOffset,
        data.byteOffset +
          data.byteLength
      )
    );

    return;
  }

  if (data instanceof Blob) {
    const buffer =
      await data.arrayBuffer();

    await handleBinaryChunk(buffer);

    return;
  }

  console.warn(
    "Unsupported incoming data type:",
    typeof data
  );
}


async function handleKeyMessage(message) {
  if (!message.key) {
    throw new Error(
      "Missing public key."
    );
  }

  if (!localKeyPair) {
    await createLocalKeyPair();
  }

  const remotePublicKey =
    await importPublicKey(
      message.key
    );

  await deriveSharedKey(
    remotePublicKey
  );

  conn.send(
    JSON.stringify({
      type: "KEY_ACK"
    })
  );
}


async function handleKeyAck() {
  if (!sharedAESKey) {
    return;
  }

  updateConnectionStatus(
    "Connected",
    true
  );
}


async function handleMetaMessage(data) {
  if (!sharedAESKey) {
    throw new Error(
      "Secure key is not available."
    );
  }

  const metadata =
    await decryptJSON(data);

  if (
    !metadata ||
    typeof metadata.name !== "string" ||
    !Number.isFinite(metadata.size) ||
    metadata.size < 0
  ) {
    throw new Error(
      "Invalid transfer metadata."
    );
  }

  if (metadata.size > MAX_FILE_SIZE) {
    throw new Error(
      "Incoming file exceeds the supported size limit."
    );
  }

  incomingMeta = metadata;

  receivedBytes = 0;
  incomingChunks = 0;
  receiveBuffer = [];

  receiveStartTime =
    performance.now();

  activeReceiveTransfer =
    createTransferCard(
      "receive",
      metadata
    );

  updateTransferCard(
    activeReceiveTransfer,
    0,
    metadata.size,
    "Receiving..."
  );
}


async function handleBinaryChunk(data) {
  if (
    !incomingMeta ||
    !activeReceiveTransfer
  ) {
    return;
  }

  const buffer =
    data instanceof ArrayBuffer
      ? data
      : data.buffer;

  const decrypted =
    await decryptBinary(buffer);

  if (
    receivedBytes +
      decrypted.byteLength >
    incomingMeta.size
  ) {
    throw new Error(
      "Received data exceeds file size."
    );
  }

  receiveBuffer.push(decrypted);

  receivedBytes +=
    decrypted.byteLength;

  incomingChunks++;

  const elapsed =
    (performance.now() -
      receiveStartTime) /
    1000;

  const speed =
    elapsed > 0
      ? receivedBytes / elapsed
      : 0;

  updateTransferCard(
    activeReceiveTransfer,
    receivedBytes,
    incomingMeta.size,
    "Receiving..."
  );

  activeReceiveTransfer.speed.textContent =
    `${formatTransferSize(speed)}/s`;
}


async function handleEndMessage() {
  if (
    !incomingMeta ||
    !activeReceiveTransfer
  ) {
    return;
  }

  if (
    receivedBytes !==
    incomingMeta.size
  ) {
    activeReceiveTransfer.label.textContent =
      "Transfer incomplete";

    activeReceiveTransfer.status.innerHTML = `
      <i data-lucide="circle-x"></i>
      <span>Incomplete</span>
    `;

    activeReceiveTransfer.speed.textContent =
      `${formatTransferSize(receivedBytes)} of ${formatTransferSize(incomingMeta.size)} received`;

    if (window.lucide) {
      lucide.createIcons();
    }

    receiveBuffer = [];
    incomingMeta = null;
    receivedBytes = 0;
    incomingChunks = 0;
    activeReceiveTransfer = null;

    return;
  }

  const blob = new Blob(
    receiveBuffer,
    {
      type:
        incomingMeta.fileType ||
        "application/octet-stream"
    }
  );

  const transfer =
    activeReceiveTransfer;

  const metadata =
    incomingMeta;

  completeTransferCard(
    transfer,
    "receive"
  );

  addDownloadToTransfer(
    transfer,
    blob,
    metadata.name
  );

  saveHistory({
    type: "received",
    name: metadata.name,
    size: metadata.size,
    timestamp: Date.now()
  });

  transfer.speed.textContent =
    `${formatTransferSize(metadata.size)} received`;

  receiveBuffer = [];
  incomingMeta = null;
  receivedBytes = 0;
  incomingChunks = 0;
  activeReceiveTransfer = null;
}


function handleFileSelection(event) {
  const file =
    event.target.files?.[0];

  if (!file) {
    return;
  }

  sendFile(file);
}


function saveHistory(item) {
  try {
    const history =
      JSON.parse(
        localStorage.getItem(
          HISTORY_KEY
        ) || "[]"
      );

    history.unshift(item);

    const limitedHistory =
      history.slice(0, 100);

    localStorage.setItem(
      HISTORY_KEY,
      JSON.stringify(
        limitedHistory
      )
    );

    renderHistory();

  } catch (error) {
    console.error(
      "Failed to save history:",
      error
    );
  }
}


function getHistory() {
  try {
    const history =
      JSON.parse(
        localStorage.getItem(
          HISTORY_KEY
        ) || "[]"
      );

    return Array.isArray(history)
      ? history
      : [];

  } catch {
    return [];
  }
}


function formatHistoryDate(timestamp) {
  const date =
    new Date(timestamp);

  return date.toLocaleString(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "short"
    }
  );
}


function renderHistory() {
  if (!historyList) {
    return;
  }

  const history =
    getHistory();

  if (history.length === 0) {
    historyList.innerHTML = `
      <div class="history-empty">
        <i data-lucide="clock-3"></i>
        <div>No transfers yet</div>
      </div>
    `;

    if (window.lucide) {
      lucide.createIcons();
    }

    return;
  }

  historyList.innerHTML =
    history
      .map(item => {
        const action =
          item.type === "sent"
            ? "Sent"
            : "Received";

        return `
          <div class="history-item">

            <div>
              <span class="history-action">
                ${action}
              </span>
              <span>
                ${escapeHTML(item.name)}
              </span>
            </div>

            <div>
              ${formatTransferSize(item.size)}
            </div>

            <div class="history-time">
              ${formatHistoryDate(item.timestamp)}
            </div>

          </div>
        `;
      })
      .join("");

  if (window.lucide) {
    lucide.createIcons();
  }
}


function clearHistory() {
  const history =
    getHistory();

  if (history.length === 0) {
    return;
  }

  const confirmed =
    window.confirm(
      "Clear all transfer history?"
    );

  if (!confirmed) {
    return;
  }

  localStorage.removeItem(
    HISTORY_KEY
  );

  renderHistory();
}


async function copyPeerId() {
  const id =
    myPeerId.textContent.trim();

  if (
    !id ||
    id === "Generating..."
  ) {
    return;
  }

  try {
    await navigator.clipboard.writeText(
      id
    );

    const original =
      copyIdBtn.innerHTML;

    copyIdBtn.innerHTML = `
      <i data-lucide="check"></i>
    `;

    if (window.lucide) {
      lucide.createIcons();
    }

    setTimeout(() => {
      copyIdBtn.innerHTML =
        original;

      if (window.lucide) {
        lucide.createIcons();
      }
    }, 1500);

  } catch (error) {
    console.error(
      "Copy failed:",
      error
    );
  }
}


fileInput.addEventListener(
  "change",
  handleFileSelection
);

connectBtn.addEventListener(
  "click",
  connectToPeer
);

copyIdBtn.addEventListener(
  "click",
  copyPeerId
);

clearHistoryBtn.addEventListener(
  "click",
  clearHistory
);

targetPeerId.addEventListener(
  "keydown",
  event => {
    if (event.key === "Enter") {
      connectToPeer();
    }
  }
);

setupTabs();

renderHistory();

showSetupSection();

if (window.lucide) {
  lucide.createIcons();
}

initPeer();