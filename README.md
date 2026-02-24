# Chain Proxy Builder

🌐 **[Farsi](README-fa.md)** | [English](README.md)

A powerful, standalone web application to chain two proxy configurations into a single **Xray** or **Sing-box** JSON configuration. This tool is specifically designed to help users combine multiple proxy layers for enhanced connection stability and fixed IP masking.

## 🚀 Features

- **Dual Config Chaining**: Easily chain a primary proxy (e.g., Worker/CDN) with a secondary chain proxy.
- **Protocol Support**: Supports **VLESS**, **VMess**, **Trojan**, **Shadowsocks**, **SOCKS**, **HTTP**, and **SSH**.
- **Dual Output**: Generates both **Xray** and **Sing-box** JSON configurations.
- **ECH Support**: Automatically parses and includes ECH config for secure connections.
- **Client-Side Only**: All processing happens in your browser. No data is sent to any server.

## 📦 Output Formats

| Output | Client |
|--------|--------|
| **Xray JSON** | Use with any Xray-compatible client (v2rayN, v2rayNG, Nekoray, etc.) |
| **Sing-box JSON** | Use with [sing-box](https://sing-box.sagernet.org/) client |

## 🔗 How it Works

The application generates a configuration that routes your traffic in this sequence:

`You ➔ Config 1 (Proxy) ➔ Config 2 (Chain) ➔ Internet`

This ensures that your final outgoing IP address is that of the **Chain Proxy**, providing a consistent identity for the websites you visit.

## 🛠️ Usage

1. **Config 1**: Paste your first proxy URL (this can be a Cloudflare Worker, CDN, or any other proxy).
2. **Config 2**: Paste your second proxy URL (the one you want to chain through).
   - For **SSH**, click the 🔑 SSH toggle and fill in server, port, username, and password.
3. **Settings**: Adjust DNS servers or SOCKS ports if needed.
4. **Generate**: Click "Generate Chained Config" to get your JSON.
5. **Deploy**: Copy the JSON or download it as a file to use in your preferred client.

## 📋 Supported Protocols

| Protocol | URL Format | Notes |
|----------|-----------|-------|
| **VLESS** | `vless://uuid@server:port?params` | |
| **VMess** | `vmess://base64-json` | |
| **Trojan** | `trojan://password@server:port?params` | |
| **Shadowsocks** | `ss://base64(method:pass)@server:port` | No transport (ws, grpc, etc.) and no TLS support |
| **SOCKS** | `socks://user:pass@server:port` | Must include username and password |
| **HTTP** | `http://user:pass@server:port` | Must include username and password |
| **SSH** | 4-field input (server, port, user, password) | **Sing-box only** — not supported by Xray |

## ⚠️ Important Notes

- **SOCKS & HTTP** configs must have **username and password** included.
- **Xray** does not support **raw** (headerless TCP) configs — use TCP with http header type instead.
- **Shadowsocks** cannot have any transport (WebSocket, gRPC, HTTPUpgrade, etc.) and cannot have TLS.
- **SSH** is only supported by **Sing-box**. When SSH is used, the Xray tab is automatically disabled. Use the [sing-box client](https://sing-box.sagernet.org/) for SSH configs.

## 🔧 Supported Transports

TCP, TCP (http header), WebSocket, gRPC, HTTPUpgrade

## 🔒 Supported TLS

TLS, Reality, None

## 📦 Tech Stack

- **HTML5**: Semantic structure.
- **CSS3**: Custom variables, glassmorphism, and animations.
- **JavaScript**: Core logic for URL parsing and JSON generation.

## 🛡️ Credits

This project draws inspiration and logic from the [BPB-Worker-Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel) project.

---
Built with ❤️ for the privacy community.