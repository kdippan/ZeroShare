# ⚡ ZeroShare | Absolute Privacy. Infinite Speed.

[![Live Demo](https://img.shields.io/badge/Live_Demo-Play_Now-10b981?style=for-the-badge&logo=vercel)](https://zeroshare-io.vercel.app/)
[![Made by Dippan](https://img.shields.io/badge/Developer-Dippan_Bhusal-6366f1?style=for-the-badge&logo=github)](https://github.com/kdippan)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

**ZeroShare** is a next-generation, browser-based file-sharing utility. It establishes a direct, peer-to-peer (P2P) tunnel between two devices, allowing them to exchange data of any size without intermediate cloud storage. Before any data leaves your device, it is encrypted using military-grade **AES-256-GCM**.

🌐 **Live URL:** [zeroshare-io.vercel.app](https://zeroshare-io.vercel.app/)

---

## ✨ Key Features

- **Zero-Knowledge Architecture:** Your files never touch a server. They are transferred directly from Browser A to Browser B.
- **End-to-End Encryption (E2EE):** Utilizes the native Web Crypto API for ECDH key exchange and AES-256-GCM chunk encryption.
- **No File Size Limits:** Instead of loading massive files into RAM, ZeroShare reads, encrypts, and streams data in 64KB chunks, preventing browser crashes on mobile devices.
- **NAT Traversal:** Built-in Google STUN and Metered TURN servers guarantee connections punch through strict corporate and mobile firewalls.
- **Local History Log:** Keeps a private, local record of your transfers and connections using `localStorage`.
- **Progressive Web App (PWA):** Fully installable on mobile and desktop devices.
- **Modern UI:** Responsive Glassmorphism design with system-aware Dark Mode and smooth CSS animations.

---

## 🏗️ How It Works (The Architecture)

ZeroShare combines two powerful web technologies to achieve secure, serverless transfers:

1. **The Handshake (WebRTC & PeerJS):** When two users enter a matching 6-character room code, PeerJS uses a lightweight signaling server to exchange their IP addresses (SDP offers). Once connected, the signaling server drops out, and a direct WebRTC `RTCDataChannel` is opened.
2. **The Key Exchange (ECDH):** Before sending files, both browsers generate an Elliptic Curve Diffie-Hellman (P-256) keypair. They swap public keys over the P2P tunnel to mathematically derive the exact same shared secret key.
3. **The Transfer (AES-GCM):**
   The sender's browser slices the file into 64KB chunks. Each chunk is encrypted with the shared AES key and a unique Initialization Vector (IV), sent over the WebRTC channel, and decrypted on the fly by the receiver. 

---

## 🚀 Tech Stack

- **Frontend:** HTML5, CSS3 (Glassmorphism UI), Vanilla JavaScript
- **Networking:** [WebRTC](https://webrtc.org/) (via [PeerJS](https://peerjs.com/))
- **Cryptography:** Native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- **Icons:** [Lucide Icons](https://lucide.dev/)
- **Hosting:** Vercel / GitHub Pages Ready

---

## 💻 Local Setup & Installation

Because ZeroShare is a 100% client-side application, running it locally requires zero build tools or dependencies.

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/kdippan/zeroshare.git](https://github.com/kdippan/zeroshare.git)

 * Open the folder:
   ```cd zeroshare```

 * Run a local server:
   You can use Live Server in VS Code, or Python's built-in HTTP server:
   ```python -m http.server 8000```

 * Open your browser:
   Navigate to ```http://localhost:8000```
☕ Support the Developer
If you found this project helpful, learned something from the code, or just want to support my work as a student developer, consider buying me a coffee!
<a href="https://www.google.com/search?q=https://www.buymeacoffee.com/dippanbhusal" target="_blank"><img src="https://i.postimg.cc/8zx4ftXP/49859-removebg-preview.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
👨‍💻 Author
Dippan Bhusal
 * GitHub: @kdippan
 * Portfolio: dippanbhusal.tech
If you like this project, please leave a ⭐ on the repository!


