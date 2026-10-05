# Proxy Builder

🌐 **[فارسی](README-fa.md)** | [English](README.md)

A powerful, standalone web application with four tools:

1. **🛡️ ECH** (default tab) — enhance a **VLESS** or **Trojan** URL by injecting `fp` (TLS fingerprint, default `chrome`) and `ech` (ECH Config List) parameters, plus a server (IP/domain) override — producing a link ready to import into your own client.
2. **🧬 Fragment + Fingerprint** — enhance a **VLESS** or **Trojan** URL by injecting `cs` (cipher suites), `fm` (fragment mask) and `fp` (TLS fingerprint) parameters, plus a server (IP/domain) override — producing a link ready to import into your own client.
3. **🔗 Chain Builder** — chain two proxy configurations into a single **Xray** or **Sing-box** JSON configuration for enhanced connection stability and fixed IP masking.
4. **📥 Subscription Import** — fetch a subscription link (or paste its contents) to decode it (plain or base64) and batch-enhance every **VLESS**/**Trojan** config inside, with copy/`.txt`/base64 export.

All processing happens in your browser. No data is sent to any server — fetching a subscription link contacts only the provider URL you entered, and pasted or dropped content never leaves your browser.

## 🚀 Features

### 🛡️ ECH
- **Paste & Enhance**: Paste single or multiple `vless://` or `trojan://` URLs (one per line) and get enhanced links with `fp` and `ech` parameters added.
- **Subscription Input**: Paste a subscription link to fetch it in your browser — or paste its contents (plain or base64) — to batch-enhance every VLESS/Trojan config inside with the same ECH options. The server override is ignored here (each config keeps its own address); changing the ECH options re-enhances the fetched configs without re-fetching.
- **Server Override**: The server (IP/domain) field is auto-filled from the URL for a single config and is user-editable. With multiple configs the field stays empty and only applies to all configs if you type a custom value (supports IPv4, IPv6 and domains).
- **Fingerprint**: Default `chrome`, with `unsafe`, `firefox`, `safari`, `random` and `none` options.
- **ECH presets**: The `ECH Server` selector ships prefilled with `cloudflare-ech.com + Cloudflare udp://1.1.1.1`; alternatives include AliDNS DoH and other public ECH servers. The field stays editable for manual tweaks.
- **Bare domains**: Typing just a domain (e.g. `cloudflare-ech.com`) auto-adds `+udp://8.8.8.8`; a base64 ECHConfigList passes through untouched.
- **TLS-aware**: `ech` is only added when the config uses `tls` security. Clear the field to skip it.
- **One-click Copy**: Copy the enhanced URL straight to the clipboard.
- **Export**: Download as `.txt` (one per line) or base64 `.txt` (standard subscription body).
- **Protocol Support**: **VLESS** and **Trojan**.

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

### 📥 Subscription Import
- **Fetch & Enhance**: Paste a subscription link to fetch it directly in your browser, decode it (plain or base64) and batch-enhance every VLESS/Trojan config inside.
- **Blocked Providers**: If the provider sends no CORS headers, the error shows 3 quick steps and an **Open link** button opens the URL in a new tab for copying.
- **Paste or Drop**: A pasted config list/base64 blob — or a dropped saved `.txt` file — is enhanced with no fetch at all.
- **Shared Options**: Uses the same `fp` / `cs` / `fm` values as the Fragment + Fingerprint tab; the server override is ignored (each config keeps its own address).
- **No ECH here**: ECH is applied only in the **ECH** tab — subscription entries never get an `ech` parameter.
- **Export**: Copy to clipboard, download as `.txt` (one per line) or base64 `.txt`.
- **Protocol Support**: **VLESS** and **Trojan** are enhanced; other protocols found inside are counted as skipped.

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

### 🛡️ ECH
1. Open the app — the **ECH** tab is active by default.
2. Paste your **VLESS** or **Trojan** URL.
3. Adjust the options if needed: server override (auto-filled from the URL), fingerprint (default `chrome`), ECH server preset or a manual value (bare domain auto-adds `+udp://8.8.8.8`).
4. Click **"Enhance URL"** and copy the resulting link — import it into your client (Xray core, Sing-box 1.13.0+, or Clash 1.19.20+).
5. For bulk configs, use the **Subscription Input** card instead: paste a link and click **"Fetch & Enhance Sub"** — or paste the subscription contents directly.

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

### 📥 Subscription Import
1. Switch to the **Subscription** tab.
2. Paste your subscription **link** and click **"Fetch & Enhance"** — or paste its **contents** (or drop a saved `.txt` file) to skip fetching.
3. If fetching is blocked, follow the 3 steps shown (open the link with **Open link**, copy, paste, fetch again).
4. Copy or download the enhanced configs (`.txt` or base64 `.txt`).

## 📋 Supported Protocols

| Protocol | URL Format | Notes |
|----------|-----------|-------|
| **VLESS** | `vless://uuid@server:port?params` | Supported by all four tools |
| **VMess** | `vmess://base64-json` | Chain Builder only |
| **Trojan** | `trojan://password@server:port?params` | Supported by all four tools |
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