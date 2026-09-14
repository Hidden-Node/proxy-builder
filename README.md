# Proxy Builder

🌐 **[فارسی](README-fa.md)** | [English](README.md)

A powerful, standalone web application with two tools:

1. **🧬 Fragment + Fingerprint** — enhance a **VLESS** or **Trojan** URL by injecting `cs` (cipher suites), `fm` (fragment mask) and `fp` (TLS fingerprint) parameters, plus a server (IP/domain) override — producing a link ready to import into your own client.
2. **🔗 Chain Builder** — chain two proxy configurations into a single **Xray** or **Sing-box** JSON configuration for enhanced connection stability and fixed IP masking.

All processing happens in your browser. No data is sent to any server.

## 🚀 Features

### 🧬 Fragment + Fingerprint
- **Paste & Enhance**: Paste single or multiple `vless://` or `trojan://` URLs (one per line) and get enhanced links with `cs`, `fm` and `fp` parameters added.
- **Multi-Config Support**: Paste bulk proxy URL lists to parse, validate, and batch enhance all URLs cleanly without remark collision.
- **Server Override**: The server (IP/domain) field is auto-filled from the URL for a single config and is user-editable. With multiple configs the field stays empty and only applies to all configs if you type a custom value (supports IPv4, IPv6 and domains).
- **Fingerprint**: Default `unsafe`, with `chrome`, `firefox`, `safari`, `random` and `none` options.
- **Fragment presets**: `fm` has `v1` (classic: `5,94,1` / `109,1` / split `355`) and `v2` (new, default: `0,104,1` / `114,1` / split `11`). Switch via the `Fragment Version` selector; the field stays editable for manual tweaks.
- **TLS-aware**: `cs` and `fm` are only added when the config uses `tls` security. Clear a field to skip that parameter.
- **One-click Copy**: Copy the enhanced URL straight to the clipboard.
- **Protocol Support**: **VLESS** and **Trojan**.

### 🔗 Chain Builder
- **Dual Config Chaining**: Easily chain a primary proxy (e.g., Worker/CDN) with a secondary chain proxy.
- **Protocol Support**: Supports **VLESS**, **VMess**, **Trojan**, **Shadowsocks**, **SOCKS**, **HTTP**, and **SSH**.
- **Dual Output**: Generates both **Xray** and **Sing-box** JSON configurations.
- **ECH Support**: Automatically parses and includes ECH config for secure connections.

| Output | Client |
|--------|--------|
| **Xray JSON** | Use with any Xray-compatible client (v2rayN, v2rayNG, Nekoray, etc.) |
| **Sing-box JSON** | Nested tabs for different client types (see below). |

### 📦 Sing-box Sub-formats
- **Standard**: The regular Sing-box configuration.
- **Nekoray**: High compatibility format optimized for **Nekoray**.
- **Nekobox (Android)**: Optimized for Android with a **TUN inbound**, ensuring proper VPN recognition (key icon) and mobile stability.

## 🔗 How the Chain Builder Works

The application generates a configuration that routes your traffic in this sequence:

`You ➔ Config 1 (Proxy) ➔ Config 2 (Chain) ➔ Internet`

This ensures that your final outgoing IP address is that of the **Chain Proxy**, providing a consistent identity for the websites you visit.

## 🛠️ Usage

### 🧬 Fragment + Fingerprint
1. Switch to the **Fragment + Fingerprint** tab.
2. Paste your **VLESS** or **Trojan** URL.
3. Adjust the options if needed: server override (auto-filled from the URL), fingerprint, cipher suites, final mask.
4. Click **"Enhance URL"** and copy the resulting link — import it into your client.

#### ✅ Client Requirements
- **Windows**: use [PattN](https://github.com/patterniha/PattN).
- **Android**: use [PattNG](https://github.com/patterniha/PattNG).

### 🔗 Chain Builder
1. **Config 1**: Paste your first proxy URL (this can be a Cloudflare Worker, CDN, or any other proxy).
2. **Config 2**: Paste your second proxy URL (the one you want to chain through).
   - For **SSH**, click the 🔑 SSH toggle and fill in server, port, username, and password.
3. **Settings**: Adjust DNS servers or SOCKS ports if needed.
4. **Generate**: Click "Generate Chained Config" to get your JSON.
5. **Deploy**: Copy the JSON or download it as a file to use in your preferred client.

## 📋 Supported Protocols

| Protocol | URL Format | Notes |
|----------|-----------|-------|
| **VLESS** | `vless://uuid@server:port?params` | Supported by both tools |
| **VMess** | `vmess://base64-json` | Chain Builder only |
| **Trojan** | `trojan://password@server:port?params` | Supported by both tools |
| **Shadowsocks** | `ss://base64(method:pass)@server:port` | Chain Builder only — no transport (ws, grpc, etc.) and no TLS support |
| **SOCKS** | `socks://user:pass@server:port` | Chain Builder only — must include username and password |
| **HTTP** | `http://user:pass@server:port` | Chain Builder only — must include username and password |
| **SSH** | 4-field input (server, port, user, password) | Chain Builder only — **Sing-box only**, not supported by Xray |

## ⚠️ Important Notes

- The **Fragment + Fingerprint** tool supports **VLESS** and **Trojan** URLs only.
- **TLS is required**: the **Fragment + Fingerprint** tool only works with configs that have **TLS** enabled (security `tls` or `reality`). Non-TLS configs are not supported and will not work.
- `cs` (cipher suites) and `fm` (final mask) are only added when the config uses **tls** security.
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
- **JavaScript**: Core logic for URL parsing, enhancement and JSON generation.

## 🛡️ Credits

- The **Fragment + Fingerprint** enhancement logic (`cs` / `fm` / `fp` injection and URL export format) is based on the [PattNG](https://github.com/patterniha/PattNG) project's export-to-clipboard behavior.
- The **Chain Builder** draws inspiration and logic from the [BPB-Worker-Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel) project and this [Sing-box configuration](https://gist.github.com/alireza-delavari/62e56af0d59c92b5b1798f1442f90f61).

---
Built with ❤️ for the privacy community.