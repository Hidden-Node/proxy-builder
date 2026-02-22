# Chain Proxy Builder

A powerful, standalone web application to chain two proxy configurations into a single Xray JSON configuration. This tool is specifically designed to help users combine multiple proxy layers for enhanced connection stability and fixed IP masking.

## 🚀 Features

- **Dual Config Chaining**: Easily chain a primary proxy (e.g., Worker/CDN) with a secondary chain proxy.
- **Protocol Support**: Supports **VLESS**, **VMess**, **Trojan**, **Shadowsocks**, **SOCKS**, and **HTTP**.
- **ECH Support**: Automatically parses and includes `echConfigList` for secure connections.
- **Xray JSON Generation**: Generates a clean, optimized JSON configuration ready for use in Xray clients.
- **Client-Side Only**: All processing happens in your browser. No data is sent to any server.

## 🔗 How it Works

The application generates a configuration that routes your traffic in this sequence:
`You ➔ Config 1 (Proxy) ➔ Config 2 (Chain) ➔ Internet`

This ensures that your final outgoing IP address is that of the **Chain Proxy**, providing a consistent identity for the websites you visit.

## 🛠️ Usage

1. **Config 1**: Paste your first proxy URL (this can be a Cloudflare Worker, CDN, or any other proxy).
2. **Config 2**: Paste your second proxy URL (the one you want to chain through).
3. **Settings**: Adjust DNS servers or SOCKS ports if needed.
4. **Generate**: Click "Generate Chained Config" to get your JSON.
5. **Deploy**: Copy the JSON or download it as a file to use in your preferred VPN client.

## 📦 Tech Stack

- **HTML5**: Semantic structure.
- **CSS3**: Custom variables, glassmorphism, and animations.
- **JavaScript**: Core logic for URL parsing and JSON generation.

## 🛡️ Credits

This project draws inspiration and logic from the [BPB-Worker-Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel) project.

---
Built with ❤️ for the privacy community.

