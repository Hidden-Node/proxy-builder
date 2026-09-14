// ===================================================================
// Proxy Builder — script.js
// Enhances proxy URLs (fragment & fingerprint) and chains two proxy
// URLs into Xray & Sing-box configs
// ===================================================================

(function () {
    'use strict';

    // ===== DOM Elements =====
    const config1Input = document.getElementById('config1-input');
    const config2Input = document.getElementById('config2-input');
    const protocol1Tag = document.getElementById('protocol1-tag');
    const protocol2Tag = document.getElementById('protocol2-tag');
    const parsed1 = document.getElementById('parsed1');
    const parsed2 = document.getElementById('parsed2');
    const clear1 = document.getElementById('clear1');
    const clear2 = document.getElementById('clear2');
    const btnGenerate = document.getElementById('btn-generate');
    const generateHint = document.getElementById('generate-hint');
    const outputSection = document.getElementById('output-section');
    const flowProxyLabel = document.getElementById('flow-proxy-label');
    const flowChainLabel = document.getElementById('flow-chain-label');
    const config1Card = document.getElementById('config1-card');
    const config2Card = document.getElementById('config2-card');

    // SSH elements
    const sshToggle1 = document.getElementById('ssh-toggle1');
    const sshToggle2 = document.getElementById('ssh-toggle2');
    const sshForm1 = document.getElementById('ssh-form1');
    const sshForm2 = document.getElementById('ssh-form2');
    const urlInputGroup1 = document.getElementById('url-input-group1');
    const urlInputGroup2 = document.getElementById('url-input-group2');

    // Xray output elements
    const outputJsonXray = document.getElementById('output-json-xray');
    const outputRemarkXray = document.getElementById('output-remark-xray');
    const btnCopyXray = document.getElementById('btn-copy-xray');
    const btnDownloadXray = document.getElementById('btn-download-xray');

    // Sing-box output elements
    const outputJsonSingbox = document.getElementById('output-json-singbox');
    const outputRemarkSingbox = document.getElementById('output-remark-singbox');
    const btnCopySingbox = document.getElementById('btn-copy-singbox');
    const btnDownloadSingbox = document.getElementById('btn-download-singbox');

    // Nekoray output elements
    const outputJsonSingboxClient = document.getElementById('output-json-singbox-client');
    const outputRemarkSingboxClient = document.getElementById('output-remark-singbox-client');
    const btnCopySingboxClient = document.getElementById('btn-copy-singbox-client');
    const btnDownloadSingboxClient = document.getElementById('btn-download-singbox-client');

    // Nekobox output elements
    const outputJsonNekobox = document.getElementById('output-json-nekobox');
    const outputRemarkNekobox = document.getElementById('output-remark-nekobox');
    const btnCopyNekobox = document.getElementById('btn-copy-nekobox');
    const btnDownloadNekobox = document.getElementById('btn-download-nekobox');

    // Tab elements
    const tabXray = document.getElementById('tab-xray');
    const tabSingbox = document.getElementById('tab-singbox');
    const tabSingboxClient = document.getElementById('tab-singbox-client');
    const panelXray = document.getElementById('panel-xray');
    const panelSingbox = document.getElementById('panel-singbox');
    const panelSingboxClient = document.getElementById('panel-singbox-client');

    // Main tab elements
    const mainTabs = document.querySelectorAll('.main-tab');
    const viewChain = document.getElementById('view-chain');
    const viewEnhancer = document.getElementById('view-enhancer');

    // Enhancer elements
    const enhancerInput = document.getElementById('enhancer-input');
    const enhancerClear = document.getElementById('enhancer-clear');
    const enhancerParsed = document.getElementById('enhancer-parsed');
    const enhancerProtocolTag = document.getElementById('enhancer-protocol-tag');
    const enhancerFp = document.getElementById('enhancer-fp');
    const enhancerCs = document.getElementById('enhancer-cs');
    const enhancerFm = document.getElementById('enhancer-fm');
    const enhancerFmPreset = document.getElementById('enhancer-fm-preset');
    const enhancerServer = document.getElementById('enhancer-server');
    const btnEnhance = document.getElementById('btn-enhance');
    const enhanceHint = document.getElementById('enhance-hint');
    const enhancerOutputSection = document.getElementById('enhancer-output-section');
    const enhancerOutputUrl = document.getElementById('enhancer-output-url');
    const enhancerOutputRemark = document.getElementById('enhancer-output-remark');
    const btnCopyEnhancer = document.getElementById('btn-copy-enhancer');
    const enhancerCard = document.getElementById('enhancer-card');

    let parsedConfig1 = null;
    let parsedConfig2 = null;
    let sshMode1 = false;
    let sshMode2 = false;
    let lastAutoServer = '';

    // ===== Base64 Helpers =====
    function safeAtob(str) {
        if (!str) return null;
        try {
            const clean = str.trim().replace(/\s+/g, '');
            if (!/^[A-Za-z0-9+/=_-]+$/.test(clean)) return null;
            const padded = clean.replace(/-/g, '+').replace(/_/g, '/');
            const pad = padded.length % 4;
            if (pad === 1) return null;
            const final = pad ? padded + '='.repeat(4 - pad) : padded;
            const decoded = decodeURIComponent(
                atob(final)
                    .split('')
                    .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                    .join('')
            );
            return decoded;
        } catch {
            try {
                const clean = str.trim().replace(/\s+/g, '');
                if (!/^[A-Za-z0-9+/=_-]+$/.test(clean)) return null;
                const padded = clean.replace(/-/g, '+').replace(/_/g, '/');
                const pad = padded.length % 4;
                if (pad === 1) return null;
                const final = pad ? padded + '='.repeat(4 - pad) : padded;
                const raw = atob(final);
                if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(raw)) return null;
                return raw;
            } catch {
                return null;
            }
        }
    }

    // Safe wrapper around decodeURIComponent: returns the raw string
    // instead of throwing on malformed percent-encoding.
    function safeDecode(str) {
        try {
            return decodeURIComponent(str);
        } catch {
            return str;
        }
    }

    // ===== URL Parser =====
    function extractLines(raw) {
        if (!raw) return [];
        return raw
            .split(/[\r\n]+/)
            .map(line => line.trim())
            .filter(line => line.length > 0);
    }

    function parseProxyURLSingle(raw) {
        const url = raw.trim();
        if (!url) return null;

        const lower = url.toLowerCase();
        if (lower.startsWith('vless://')) return parseVless(url);
        if (lower.startsWith('vmess://')) return parseVmess(url);
        if (lower.startsWith('trojan://')) return parseTrojan(url);
        if (lower.startsWith('ss://')) return parseShadowsocks(url);
        // Note: socks4/socks4a are intentionally not routed here. Xray outbound
        // only supports SOCKS5 and this app always emits version 5 for sing-box,
        // so accepting socks4 input would silently misrepresent the protocol.
        if (lower.startsWith('tg://socks') || lower.startsWith('tg://socks5') || lower.startsWith('https://t.me/socks') || lower.startsWith('http://t.me/socks') || lower.startsWith('socks://') || lower.startsWith('socks5://')) return parseSocks(url);
        if (lower.startsWith('http://') || lower.startsWith('https://')) return parseHttp(url);

        try {
            const decoded = safeAtob(url);
            if (decoded) {
                if (decoded.includes('"add"')) {
                    return parseVmess('vmess://' + url);
                }
                const decodedLower = decoded.toLowerCase();
                if (decodedLower.startsWith('vless://') || decodedLower.startsWith('vmess://') || decodedLower.startsWith('trojan://') || decodedLower.startsWith('ss://') || decodedLower.startsWith('socks://') || decodedLower.startsWith('socks5://') || decodedLower.startsWith('http://') || decodedLower.startsWith('https://') || decodedLower.startsWith('tg://')) {
                    return parseProxyURLSingle(decoded);
                }
                if (decoded.includes('@') && decoded.includes(':')) {
                    return parseSocks('socks5://' + decoded);
                }
            }
        } catch { }

        // Note: socks4/socks4a links fall through to this error on purpose.
        // Only SOCKS5 is supported (Xray outbound is SOCKS5-only).
        return { error: 'Unknown protocol. Supported: vless, vmess, trojan, ss, socks (socks5 only), http' };
    }

    function parseProxyURL(raw) {
        const lines = extractLines(raw);
        if (lines.length === 0) return null;
        if (lines.length === 1) return parseProxyURLSingle(lines[0]);

        const parsedList = lines.map(line => parseProxyURLSingle(line));
        const validList = parsedList.filter(p => p && !p.error);
        if (validList.length > 0) {
            return validList;
        }
        return parsedList[0] || { error: 'Unknown protocol. Supported: vless, vmess, trojan, ss, socks (socks5 only), http' };
    }

    // ===== SSH Parser (reads from form fields) =====
    function parseSSH(configNum) {
        const server = document.getElementById(`ssh-server${configNum}`).value.trim();
        const port = parseInt(document.getElementById(`ssh-port${configNum}`).value) || 22;
        const user = document.getElementById(`ssh-user${configNum}`).value.trim() || 'root';
        const password = document.getElementById(`ssh-pass${configNum}`).value;

        if (!server) return null;
        if (!password) return { error: 'Password is required for SSH' };

        return {
            protocol: 'ssh',
            server: server,
            port: port,
            user: user,
            password: password,
            remark: `SSH ${server}:${port}`
        };
    }

    function parseVless(url) {
        try {
            const u = new URL(url);
            const params = Object.fromEntries(u.searchParams);
            return {
                protocol: 'vless',
                uuid: u.username || safeDecode(url.split('://')[1].split('@')[0]),
                server: u.hostname,
                port: parseInt(u.port) || 443,
                remark: safeDecode(u.hash.slice(1) || ''),
                type: params.type || 'tcp',
                headerType: params.headerType || 'none',
                host: params.host || undefined,
                path: params.path || undefined,
                serviceName: params.serviceName || undefined,
                authority: params.authority || undefined,
                mode: params.mode || undefined,
                security: params.security || 'none',
                sni: params.sni || undefined,
                fp: params.fp || 'chrome',
                alpn: params.alpn || undefined,
                pbk: params.pbk || undefined,
                sid: params.sid || undefined,
                spx: params.spx || undefined,
                flow: params.flow || undefined,
                encryption: params.encryption || 'none',
                // ECH support
                ech: params.ech || undefined,
                // Insecure support
                allowInsecure: params.allowInsecure === '1' || params.allowInsecure === 'true' || params.insecure === '1' || params.insecure === 'true'
            };
        } catch (e) {
            return { error: 'Failed to parse VLESS URL: ' + e.message };
        }
    }

    function parseVmess(url) {
        try {
            // Case-insensitive scheme strip: the router already accepts VMESS://
            const b64 = url.replace(/^vmess:\/\//i, '');
            const decoded = safeAtob(b64);
            if (!decoded) return { error: 'Failed to decode VMess base64' };
            const config = JSON.parse(decoded);
            return {
                protocol: 'vmess',
                uuid: config.id,
                server: config.add,
                port: parseInt(config.port) || 443,
                aid: parseInt(config.aid) || 0,
                remark: config.ps || '',
                type: config.net || 'tcp',
                headerType: config.type || 'none',
                host: config.host || undefined,
                path: config.path || undefined,
                serviceName: config.path || undefined,
                authority: config.authority || undefined,
                security: config.tls || 'none',
                sni: config.sni || undefined,
                fp: config.fp || 'chrome',
                alpn: config.alpn || undefined,
                allowInsecure: config.tls === 'tls' && (config.allowInsecure === 1 || config.allowInsecure === true || config.insecure === 1 || config.insecure === true)
            };
        } catch (e) {
            return { error: 'Failed to parse VMess URL: ' + e.message };
        }
    }

    function parseTrojan(url) {
        try {
            const u = new URL(url);
            const params = Object.fromEntries(u.searchParams);
            return {
                protocol: 'trojan',
                password: safeDecode(u.username || url.split('://')[1].split('@')[0]),
                server: u.hostname,
                port: parseInt(u.port) || 443,
                remark: safeDecode(u.hash.slice(1) || ''),
                type: params.type || 'tcp',
                headerType: params.headerType || 'none',
                host: params.host || undefined,
                path: params.path || undefined,
                serviceName: params.serviceName || undefined,
                authority: params.authority || undefined,
                mode: params.mode || undefined,
                security: params.security || 'tls',
                sni: params.sni || undefined,
                fp: params.fp || 'chrome',
                alpn: params.alpn || undefined,
                pbk: params.pbk || undefined,
                sid: params.sid || undefined,
                spx: params.spx || undefined,
                ech: params.ech || undefined,
                allowInsecure: params.allowInsecure === '1' || params.allowInsecure === 'true' || params.insecure === '1' || params.insecure === 'true'
            };
        } catch (e) {
            return { error: 'Failed to parse Trojan URL: ' + e.message };
        }
    }

    function parseShadowsocks(url) {
        try {
            // Case-insensitive scheme strip: the router already accepts SS://
            let raw = url.replace(/^ss:\/\//i, '');
            const hashIdx = raw.indexOf('#');
            let remark = '';
            if (hashIdx !== -1) {
                remark = safeDecode(raw.slice(hashIdx + 1));
                raw = raw.slice(0, hashIdx);
            }

            let method, password, server, port;

            if (raw.includes('@')) {
                const [userPart, hostPart] = raw.split('@');
                const decoded = safeAtob(userPart) || userPart;
                const colonIdx = decoded.indexOf(':');
                method = decoded.slice(0, colonIdx);
                password = decoded.slice(colonIdx + 1);
                const hostMatch = hostPart.match(/^(.+):(\d+)/);
                if (hostMatch) {
                    server = hostMatch[1];
                    port = parseInt(hostMatch[2]);
                }
            } else {
                const decoded = safeAtob(raw);
                if (!decoded) return { error: 'Failed to decode SS base64' };
                const match = decoded.match(/^(.+?):(.+)@(.+):(\d+)/);
                if (match) {
                    method = match[1];
                    password = match[2];
                    server = match[3];
                    port = parseInt(match[4]);
                }
            }

            if (!server) return { error: 'Failed to parse Shadowsocks URL' };

            return {
                protocol: 'shadowsocks',
                method: method,
                password: password,
                server: server,
                port: port,
                remark: remark
            };
        } catch (e) {
            return { error: 'Failed to parse Shadowsocks URL: ' + e.message };
        }
    }

    function parseSocks(url) {
        try {
            let target = url.trim();
            let remark = '';
            let user, pass, server, port;

            const lower = target.toLowerCase();
            if (lower.startsWith('tg://socks') || lower.startsWith('tg://socks5') || lower.startsWith('https://t.me/socks') || lower.startsWith('http://t.me/socks')) {
                // Telegram share format carries plain SOCKS5 credentials as query params.
                // The output is still a standard SOCKS outbound, so Xray/sing-box support it.
                const u = new URL(/^tg:\/\//i.test(target) ? target.replace(/^tg:\/\/(socks5|socks)\?/i, 'http://localhost/?') : target);
                server = u.searchParams.get('server') || u.searchParams.get('host') || u.searchParams.get('ip') || '';
                port = parseInt(u.searchParams.get('port')) || 1080;
                user = u.searchParams.get('user') || u.searchParams.get('username') || undefined;
                pass = u.searchParams.get('pass') || u.searchParams.get('password') || undefined;
                // The hash fragment needs decoding, but query params are already
                // decoded by URLSearchParams, so decoding them again would throw
                // on values like "100%".
                const tgHash = u.hash.slice(1);
                remark = tgHash ? safeDecode(tgHash) : (u.searchParams.get('remark') || '');

                if (!server) return { error: 'Failed to parse Telegram SOCKS URL: missing server' };
                return {
                    protocol: 'socks',
                    server: server,
                    port: port,
                    user: user || undefined,
                    pass: pass || undefined,
                    remark: remark
                };
            }

            // Only socks:// and socks5:// are supported here. socks4/socks4a
            // input is rejected by the router on purpose (see above).
            let body = target.replace(/^(socks5:\/\/|socks:\/\/)/i, '');

            const hashIdx = body.indexOf('#');
            if (hashIdx !== -1) {
                remark = safeDecode(body.slice(hashIdx + 1));
                body = body.slice(0, hashIdx);
            }

            if (!body.includes('@')) {
                const decodedBody = safeAtob(body);
                if (decodedBody && (decodedBody.includes(':') || decodedBody.includes('@'))) {
                    if (!remark && decodedBody.includes('#')) {
                        const dHashIdx = decodedBody.indexOf('#');
                        remark = safeDecode(decodedBody.slice(dHashIdx + 1));
                        body = decodedBody.slice(0, dHashIdx);
                    } else {
                        body = decodedBody;
                    }
                }
            }

            let userPart = '';
            let hostPart = body;

            if (body.includes('@')) {
                const atIdx = body.lastIndexOf('@');
                userPart = body.slice(0, atIdx);
                hostPart = body.slice(atIdx + 1);
            }

            if (userPart) {
                if (userPart.includes(':')) {
                    const colonIdx = userPart.indexOf(':');
                    user = safeDecode(userPart.slice(0, colonIdx));
                    pass = safeDecode(userPart.slice(colonIdx + 1));
                } else {
                    const decodedUser = safeAtob(userPart);
                    if (decodedUser && decodedUser.includes(':')) {
                        const colonIdx = decodedUser.indexOf(':');
                        user = decodedUser.slice(0, colonIdx);
                        pass = decodedUser.slice(colonIdx + 1);
                    } else {
                        user = safeDecode(userPart);
                    }
                }
            }

            let searchParams = null;
            if (hostPart.includes('?')) {
                const qIdx = hostPart.indexOf('?');
                try {
                    searchParams = new URLSearchParams(hostPart.slice(qIdx + 1));
                } catch { }
                hostPart = hostPart.slice(0, qIdx);
            }
            hostPart = hostPart.replace(/\/+$/, '');

            if (hostPart.startsWith('[')) {
                const closeBracket = hostPart.indexOf(']');
                if (closeBracket !== -1) {
                    server = hostPart.slice(1, closeBracket);
                    const portPart = hostPart.slice(closeBracket + 1);
                    if (portPart.startsWith(':')) {
                        port = parseInt(portPart.slice(1)) || 1080;
                    } else {
                        port = 1080;
                    }
                } else {
                    server = hostPart;
                    port = 1080;
                }
            } else if (hostPart.includes(':')) {
                const lastColon = hostPart.lastIndexOf(':');
                server = hostPart.slice(0, lastColon);
                port = parseInt(hostPart.slice(lastColon + 1)) || 1080;
            } else {
                server = hostPart;
                port = 1080;
            }

            if (searchParams) {
                if (!user && (searchParams.get('user') || searchParams.get('username'))) {
                    user = searchParams.get('user') || searchParams.get('username');
                }
                if (!pass && (searchParams.get('pass') || searchParams.get('password'))) {
                    pass = searchParams.get('pass') || searchParams.get('password');
                }
                if (!remark && searchParams.get('remark')) {
                    remark = searchParams.get('remark');
                }
            }

            if (!server) return { error: 'Failed to parse SOCKS URL: missing server' };

            return {
                protocol: 'socks',
                server: server,
                port: port,
                user: user || undefined,
                pass: pass || undefined,
                remark: remark
            };
        } catch (e) {
            return { error: 'Failed to parse SOCKS URL: ' + e.message };
        }
    }

    function parseHttp(url) {
        try {
            let target = url.trim();
            let remark = '';
            let user, pass, server, port;

            const lower = target.toLowerCase();
            if (lower.startsWith('tg://http') || lower.startsWith('https://t.me/http') || lower.startsWith('http://t.me/http')) {
                const u = new URL(/^tg:\/\//i.test(target) ? target.replace(/^tg:\/\/http\?/i, 'http://localhost/?') : target);
                server = u.searchParams.get('server') || u.searchParams.get('host') || u.searchParams.get('ip') || '';
                port = parseInt(u.searchParams.get('port')) || 80;
                user = u.searchParams.get('user') || u.searchParams.get('username') || undefined;
                pass = u.searchParams.get('pass') || u.searchParams.get('password') || undefined;
                // Same double-decode guard as in parseSocks: hash needs decoding,
                // query params are already decoded by URLSearchParams.
                const tgHash = u.hash.slice(1);
                remark = tgHash ? safeDecode(tgHash) : (u.searchParams.get('remark') || '');

                if (!server) return { error: 'Failed to parse HTTP URL: missing server' };
                return {
                    protocol: 'http',
                    server: server,
                    port: port,
                    user: user || undefined,
                    pass: pass || undefined,
                    remark: remark
                };
            }

            let body = target.replace(/^(https:\/\/|http:\/\/)/i, '');

            const hashIdx = body.indexOf('#');
            if (hashIdx !== -1) {
                remark = safeDecode(body.slice(hashIdx + 1));
                body = body.slice(0, hashIdx);
            }

            if (!body.includes('@')) {
                const decodedBody = safeAtob(body);
                if (decodedBody && (decodedBody.includes(':') || decodedBody.includes('@'))) {
                    if (!remark && decodedBody.includes('#')) {
                        const dHashIdx = decodedBody.indexOf('#');
                        remark = safeDecode(decodedBody.slice(dHashIdx + 1));
                        body = decodedBody.slice(0, dHashIdx);
                    } else {
                        body = decodedBody;
                    }
                }
            }

            let userPart = '';
            let hostPart = body;

            if (body.includes('@')) {
                const atIdx = body.lastIndexOf('@');
                userPart = body.slice(0, atIdx);
                hostPart = body.slice(atIdx + 1);
            }

            if (userPart) {
                if (userPart.includes(':')) {
                    const colonIdx = userPart.indexOf(':');
                    user = safeDecode(userPart.slice(0, colonIdx));
                    pass = safeDecode(userPart.slice(colonIdx + 1));
                } else {
                    const decodedUser = safeAtob(userPart);
                    if (decodedUser && decodedUser.includes(':')) {
                        const colonIdx = decodedUser.indexOf(':');
                        user = decodedUser.slice(0, colonIdx);
                        pass = decodedUser.slice(colonIdx + 1);
                    } else {
                        user = safeDecode(userPart);
                    }
                }
            }

            let searchParams = null;
            if (hostPart.includes('?')) {
                const qIdx = hostPart.indexOf('?');
                try {
                    searchParams = new URLSearchParams(hostPart.slice(qIdx + 1));
                } catch { }
                hostPart = hostPart.slice(0, qIdx);
            }
            hostPart = hostPart.replace(/\/+$/, '');

            if (hostPart.startsWith('[')) {
                const closeBracket = hostPart.indexOf(']');
                if (closeBracket !== -1) {
                    server = hostPart.slice(1, closeBracket);
                    const portPart = hostPart.slice(closeBracket + 1);
                    if (portPart.startsWith(':')) {
                        port = parseInt(portPart.slice(1)) || 80;
                    } else {
                        port = 80;
                    }
                } else {
                    server = hostPart;
                    port = 80;
                }
            } else if (hostPart.includes(':')) {
                const lastColon = hostPart.lastIndexOf(':');
                server = hostPart.slice(0, lastColon);
                port = parseInt(hostPart.slice(lastColon + 1)) || 80;
            } else {
                server = hostPart;
                port = 80;
            }

            if (searchParams) {
                if (!user && (searchParams.get('user') || searchParams.get('username'))) {
                    user = searchParams.get('user') || searchParams.get('username');
                }
                if (!pass && (searchParams.get('pass') || searchParams.get('password'))) {
                    pass = searchParams.get('pass') || searchParams.get('password');
                }
                if (!remark && searchParams.get('remark')) {
                    remark = searchParams.get('remark');
                }
            }

            if (!server) return { error: 'Failed to parse HTTP URL: missing server' };

            return {
                protocol: 'http',
                server: server,
                port: port,
                user: user || undefined,
                pass: pass || undefined,
                remark: remark
            };
        } catch (e) {
            return { error: 'Failed to parse HTTP URL: ' + e.message };
        }
    }

    // ===== URL Enhancer (Fragment + Fingerprint) =====

    function enhanceURL(raw) {
        const url = raw.trim();
        if (!url) return { error: 'No URL provided' };
        if (!url.startsWith('vless://') && !url.startsWith('trojan://')) {
            return { error: 'Only VLESS and Trojan URLs are supported' };
        }

        let u;
        try {
            u = new URL(url);
        } catch (e) {
            return { error: 'Failed to parse URL: ' + e.message };
        }

        const params = u.searchParams;
        const security = params.get('security') || 'none';

        // Server override — auto-filled from URL, user-editable, empty keeps original
        const server = enhancerServer.value.trim();
        if (server) {
            const host = server.includes(':') && !server.startsWith('[')
                ? '[' + server + ']'
                : server;
            try {
                u.hostname = host;
            } catch (e) {
                return { error: 'Invalid server address: ' + e.message };
            }
        }

        // Fingerprint — always applied when selected value is non-empty
        const fp = enhancerFp.value.trim();
        if (fp && fp !== 'none') {
            params.set('fp', fp);
        }

        // Cipher suites & fragment mask — only meaningful with TLS
        if (security === 'tls') {
            const cs = enhancerCs.value.trim();
            if (cs) {
                params.set('cs', cs);
            }
            const fm = enhancerFm.value.trim();
            if (fm) {
                params.set('fm', fm);
            }
        }

        // URLSearchParams encodes spaces as '+', but v2ray-style clients use '%20'
        u.search = u.search.replace(/\+/g, '%20');

        return { url: u.toString() };
    }

    function onEnhancerInput() {
        const val = enhancerInput.value.trim();
        const lines = extractLines(val);
        let parsedList = [];
        let unsupportedCount = 0;
        let invalidCount = 0;

        if (lines.length > 0) {
            lines.forEach(line => {
                const p = parseProxyURLSingle(line);
                if (p && !p.error) {
                    if (p.protocol === 'vless' || p.protocol === 'trojan') {
                        parsedList.push(p);
                    } else {
                        unsupportedCount++;
                    }
                } else {
                    invalidCount++;
                }
            });
        }

        // Auto-fill the server field from the URL — only for a single config.
        // With multiple configs, auto-filling from the first URL would silently
        // override every config's server with the first one's. A user-typed
        // custom value is kept: it acts as a deliberate override for all configs.
        if (parsedList.length === 1) {
            const firstServer = parsedList[0].server || '';
            const current = enhancerServer.value.trim();
            if (!current || current === lastAutoServer || current === firstServer) {
                enhancerServer.value = firstServer;
                lastAutoServer = firstServer;
            }
        } else if (parsedList.length > 1) {
            const current = enhancerServer.value.trim();
            if (!current || current === lastAutoServer) {
                enhancerServer.value = '';
                lastAutoServer = '';
            }
        } else if (!enhancerServer.value.trim()) {
            lastAutoServer = '';
        }

        if (lines.length > 0) {
            if (parsedList.length > 0) {
                renderParsedInfo(parsedList.length === 1 ? parsedList[0] : parsedList, enhancerParsed);
                const protocols = Array.from(new Set(parsedList.map(p => p.protocol)));
                if (protocols.length === 1) {
                    updateProtocolTag(enhancerProtocolTag, parsedList[0]);
                } else {
                    enhancerProtocolTag.textContent = 'MULTI';
                    enhancerProtocolTag.classList.add('active');
                    enhancerProtocolTag.style.color = '#7c5cff';
                    enhancerProtocolTag.style.borderColor = '#7c5cff4d';
                    enhancerProtocolTag.style.background = '#7c5cff1a';
                }
            } else {
                renderParsedInfo({
                    error: unsupportedCount > 0
                        ? 'Only VLESS and Trojan URLs are supported'
                        : 'Failed to parse URL'
                }, enhancerParsed);
                updateProtocolTag(enhancerProtocolTag, null);
            }
        } else {
            renderParsedInfo(null, enhancerParsed);
            updateProtocolTag(enhancerProtocolTag, null);
        }

        enhancerCard.classList.remove('valid', 'invalid');
        if (lines.length > 0 && parsedList.length > 0) {
            enhancerCard.classList.add('valid');
        } else if (lines.length > 0) {
            enhancerCard.classList.add('invalid');
        }

        const count = parsedList.length;
        btnEnhance.disabled = count === 0;
        btnEnhance.innerHTML = `<span class="btn-icon">✨</span> Enhance ${count > 1 ? count + ' URLs' : 'URL'}`;
        enhanceHint.textContent = count > 0
            ? `Ready to enhance ${count} URL${count > 1 ? 's' : ''}!`
            : 'Paste VLESS or Trojan URL(s) above to enable';
        enhanceHint.style.color = count > 0 ? '#4cdf86' : '';
    }

    function onEnhance() {
        const val = enhancerInput.value.trim();
        const lines = extractLines(val);
        if (lines.length === 0) {
            enhancerOutputSection.style.display = 'none';
            return;
        }

        const enhancedUrls = [];
        lines.forEach(line => {
            const p = parseProxyURLSingle(line);
            if (p && !p.error && (p.protocol === 'vless' || p.protocol === 'trojan')) {
                const res = enhanceURL(line);
                if (res && res.url) {
                    enhancedUrls.push(res.url);
                }
            }
        });

        if (enhancedUrls.length === 0) {
            enhancerOutputSection.style.display = 'none';
            return;
        }

        const count = enhancedUrls.length;
        const firstParsed = parseProxyURLSingle(lines[0]);
        const remark = count === 1
            ? (firstParsed && firstParsed.remark
                ? `✨ ${firstParsed.protocol.toUpperCase()} ${firstParsed.server}:${firstParsed.port} | enhanced`
                : '✨ Enhanced')
            : `✨ Enhanced ${count} URLs`;

        enhancerOutputRemark.textContent = remark;
        enhancerOutputUrl.textContent = enhancedUrls.join('\n\n');
        enhancerOutputSection.style.display = 'block';
        enhancerOutputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ===== Xray Outbound Builders =====

    function buildStreamSettings(params, isChain) {
        const stream = {};
        const netType = params.type || 'tcp';

        // Network
        stream.network = netType;

        // Security
        const security = params.security || 'none';
        stream.security = security;

        // Sockopt
        if (isChain) {
            stream.sockopt = {
                domainStrategy: 'UseIPv4',
                dialerProxy: 'proxy'
            };
        } else {
            stream.sockopt = {
                domainStrategy: 'UseIP'
            };
        }

        // Transport settings — only add when there's actual content
        switch (netType) {
            case 'ws':
                stream.wsSettings = {};
                if (params.host) stream.wsSettings.host = params.host;
                if (params.path) stream.wsSettings.path = params.path;
                if (!params.host && !params.path) stream.wsSettings.path = '/';
                break;

            case 'grpc':
                stream.grpcSettings = {};
                if (params.authority) stream.grpcSettings.authority = params.authority;
                if (params.mode) stream.grpcSettings.multiMode = params.mode === 'multi';
                if (params.serviceName) stream.grpcSettings.serviceName = params.serviceName;
                break;

            case 'httpupgrade':
                stream.httpupgradeSettings = {};
                if (params.host) stream.httpupgradeSettings.host = params.host;
                stream.httpupgradeSettings.path = params.path || '/';
                break;

            case 'tcp':
            case 'raw':
                // Only add rawSettings if headerType is 'http'
                if (params.headerType === 'http') {
                    stream.rawSettings = {
                        header: {
                            type: 'http',
                            request: {
                                headers: {},
                                path: params.path ? params.path.split(',') : ['/'],
                                method: 'GET',
                                version: '1.1'
                            }
                        }
                    };
                    if (params.host) {
                        stream.rawSettings.header.request.headers.Host = params.host.split(',');
                    }
                }
                // For plain TCP (headerType=none), no rawSettings needed
                break;
        }

        // TLS settings
        if (security === 'tls') {
            stream.tlsSettings = {
                serverName: params.sni || params.server,
                fingerprint: params.fp || 'chrome',
                alpn: params.alpn ? params.alpn.split(',') : ['http/1.1'],
                allowInsecure: !!params.allowInsecure
            };
            // ECH support
            if (params.ech) {
                stream.tlsSettings.echConfigList = params.ech;
            }
        } else if (security === 'reality') {
            stream.realitySettings = {
                serverName: params.sni || params.server,
                fingerprint: params.fp || 'chrome',
                publicKey: params.pbk || '',
                shortId: params.sid || '',
                spiderX: params.spx || '',
                show: false,
                allowInsecure: !!params.allowInsecure
            };
        }

        return stream;
    }

    function buildProxyOutbound(params) {
        const streamSettings = buildStreamSettings(params, false);
        const outbound = {
            protocol: params.protocol === 'shadowsocks' ? 'shadowsocks' : params.protocol,
            tag: 'proxy'
        };

        switch (params.protocol) {
            case 'vless':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            encryption: params.encryption || 'none'
                        }]
                    }]
                };
                if (params.flow) outbound.settings.vnext[0].users[0].flow = params.flow;
                break;

            case 'vmess':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            alterId: params.aid || 0,
                            security: 'auto'
                        }]
                    }]
                };
                break;

            case 'trojan':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        password: params.password
                    }]
                };
                break;

            case 'shadowsocks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        method: params.method,
                        password: params.password
                    }]
                };
                break;

            case 'socks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                // Xray requires both user and pass for authenticated SOCKS/HTTP.
                // A user-only credential must not emit an empty password.
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            case 'http':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                // Xray requires both user and pass for authenticated SOCKS/HTTP.
                // A user-only credential must not emit an empty password.
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            default:
                return null;
        }

        outbound.streamSettings = streamSettings;
        return outbound;
    }

    function buildChainOutbound(params) {
        const streamSettings = buildStreamSettings(params, true);
        const outbound = {
            protocol: params.protocol === 'shadowsocks' ? 'shadowsocks' : params.protocol,
            tag: 'chain'
        };

        switch (params.protocol) {
            case 'vless':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            encryption: params.encryption || 'none'
                        }]
                    }]
                };
                break;

            case 'vmess':
                outbound.settings = {
                    vnext: [{
                        address: params.server,
                        port: params.port,
                        users: [{
                            id: params.uuid,
                            alterId: params.aid || 0,
                            security: 'auto'
                        }]
                    }]
                };
                break;

            case 'trojan':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        password: params.password
                    }]
                };
                break;

            case 'shadowsocks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port,
                        method: params.method,
                        password: params.password
                    }]
                };
                break;

            case 'socks':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                // Xray requires both user and pass for authenticated SOCKS/HTTP.
                // A user-only credential must not emit an empty password.
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            case 'http':
                outbound.settings = {
                    servers: [{
                        address: params.server,
                        port: params.port
                    }]
                };
                // Xray requires both user and pass for authenticated SOCKS/HTTP.
                // A user-only credential must not emit an empty password.
                if (params.user && params.pass) {
                    outbound.settings.servers[0].users = [{
                        user: params.user,
                        pass: params.pass
                    }];
                }
                break;

            default:
                return null;
        }

        outbound.streamSettings = streamSettings;
        return outbound;
    }

    // ===== Full Config Generator =====
    function generateFullConfig(config1, config2) {
        const dnsServer = document.getElementById('dns-server').value;
        const socksPort = parseInt(document.getElementById('socks-port').value) || 10808;
        const logLevel = document.getElementById('log-level').value;

        const proxyOutbound = buildProxyOutbound(config1);
        const chainOutbound = buildChainOutbound(config2);

        const remark = `🔗 ${config1.protocol.toUpperCase()} → ${config2.protocol.toUpperCase()} | ${config2.server}:${config2.port}`;

        const fullConfig = {
            remarks: remark,
            log: {
                loglevel: logLevel
            },
            dns: {
                servers: [
                    {
                        address: dnsServer,
                        tag: 'remote-dns'
                    }
                ],
                queryStrategy: 'UseIP',
                tag: 'dns'
            },
            inbounds: [
                {
                    listen: '127.0.0.1',
                    port: socksPort,
                    protocol: 'socks',
                    settings: {
                        auth: 'noauth',
                        udp: true
                    },
                    tag: 'mixed-in',
                    sniffing: {
                        enabled: true,
                        destOverride: ['http', 'tls']
                    }
                }
            ],
            outbounds: [
                chainOutbound,
                proxyOutbound,
                {
                    protocol: 'dns',
                    tag: 'dns-out'
                },
                {
                    protocol: 'freedom',
                    tag: 'direct',
                    settings: {
                        domainStrategy: 'UseIP'
                    }
                },
                {
                    protocol: 'blackhole',
                    tag: 'block'
                }
            ],
            routing: {
                domainStrategy: 'IPIfNonMatch',
                rules: [
                    {
                        inboundTag: ['remote-dns'],
                        outboundTag: 'proxy',
                        type: 'field'
                    },
                    {
                        network: 'tcp',
                        outboundTag: 'chain',
                        type: 'field'
                    },
                    {
                        protocol: ['dns'],
                        outboundTag: 'dns-out',
                        type: 'field'
                    }
                ]
            }
        };

        return { config: fullConfig, remark };
    }

    // ===== Sing-box Config Generator =====
    function generateSingboxConfig(config1, config2) {
        const dnsServer = document.getElementById('dns-server').value;
        const logLevel = document.getElementById('log-level').value;

        const remark = `🔗 ${config1.protocol.toUpperCase()} → ${config2.protocol.toUpperCase()} | ${config2.server}:${config2.port}`;

        // Build proxy outbound (config1)
        const proxyOutbound = buildSingboxOutbound(config1, 'proxy', null);
        // Build chain outbound (config2) — detours through proxy
        const chainOutbound = buildSingboxOutbound(config2, 'chain', 'proxy');

        // Map log level for Sing-box
        const sbLogLevel = logLevel === 'none' ? undefined : (logLevel === 'warning' ? 'warn' : logLevel);

        // Parse DNS host from URL
        let dnsHost = '8.8.8.8';
        let dnsType = 'https';
        try {
            const dnsUrl = new URL(dnsServer);
            dnsHost = dnsUrl.hostname;
            dnsType = dnsUrl.protocol.replace(':', '');
        } catch { }

        // Collect domains to bypass DNS (to prevent loopback)
        const bypassDomains = new Set();
        [config1, config2].forEach(cfg => {
            if (cfg.server && !cfg.server.match(/^(?:\d{1,3}\.){3}\d{1,3}$/)) bypassDomains.add(cfg.server);
            if (cfg.sni) bypassDomains.add(cfg.sni);
            if (cfg.host) {
                cfg.host.split(',').forEach(h => bypassDomains.add(h.trim()));
            }
            if (cfg.ech) {
                const echDomain = cfg.ech.split('+')[0];
                if (echDomain) bypassDomains.add(echDomain);
            }
        });

        const singboxConfig = {
            log: {
                disabled: logLevel === 'none',
                level: sbLogLevel,
                timestamp: true
            },
            dns: {
                servers: [
                    {
                        type: dnsType,
                        server: dnsHost,
                        detour: 'chain',
                        tag: 'dns-remote'
                    },
                    {
                        type: 'local',
                        tag: 'dns-direct'
                    }
                ],
                rules: [
                    {
                        clash_mode: 'Direct',
                        server: 'dns-direct'
                    },
                    {
                        clash_mode: 'Global',
                        server: 'dns-remote'
                    },
                    {
                        domain: Array.from(bypassDomains),
                        server: 'dns-direct'
                    }
                ],
                strategy: 'ipv4_only',
                independent_cache: true
            },
            inbounds: [
                {
                    type: 'tun',
                    tag: 'tun-in',
                    address: ['172.19.0.1/28'],
                    mtu: 9000,
                    auto_route: true,
                    strict_route: true,
                    stack: 'mixed'
                },
                {
                    type: 'mixed',
                    tag: 'mixed-in',
                    listen: '127.0.0.1',
                    listen_port: 2080
                }
            ],
            outbounds: [
                chainOutbound,
                proxyOutbound,
                {
                    type: 'direct',
                    tag: 'direct'
                }
            ],
            route: {
                rules: [
                    {
                        ip_cidr: '172.19.0.2',
                        action: 'hijack-dns'
                    },
                    {
                        domain: Array.from(bypassDomains),
                        outbound: 'direct'
                    },
                    {
                        clash_mode: 'Direct',
                        outbound: 'direct'
                    },
                    {
                        action: 'sniff'
                    },
                    {
                        protocol: 'dns',
                        action: 'hijack-dns'
                    },
                    {
                        ip_is_private: true,
                        outbound: 'direct'
                    },
                    {
                        network: 'udp',
                        action: 'reject'
                    }
                ],
                auto_detect_interface: true,
                default_domain_resolver: {
                    server: 'dns-direct',
                    strategy: 'ipv4_only',
                    rewrite_ttl: 60
                },
                final: 'chain'
            },
            ntp: {
                enabled: true,
                server: 'time.cloudflare.com',
                server_port: 123,
                domain_resolver: 'dns-direct',
                interval: '30m',
                write_to_system: false
            },
            experimental: {
                cache_file: {
                    enabled: true,
                    store_fakeip: true
                },
                clash_api: {
                    external_controller: '127.0.0.1:9090',
                    external_ui: 'ui',
                    default_mode: 'Rule',
                    external_ui_download_url: 'https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip',
                    external_ui_download_detour: 'direct'
                }
            }
        };

        return { config: singboxConfig, remark };
    }

    // ===== Nekoray Config Generator (Sing-box compatible) =====
    function generateSingboxClientConfig(config1, config2) {
        const dnsServer = document.getElementById('dns-server').value;
        const logLevel = document.getElementById('log-level').value;

        const remark = `🔗 NEKORAY: ${config1.protocol.toUpperCase()} → ${config2.protocol.toUpperCase()} | ${config2.server}:${config2.port}`;

        // Build hop-1 outbound (config1)
        const hop1Outbound = buildSingboxOutbound(config1, 'hop-1', null);
        // Force xudp for vless if not set
        if (config1.protocol === 'vless' && !hop1Outbound.packet_encoding) {
            hop1Outbound.packet_encoding = 'xudp';
        }

        // Build proxy outbound (config2) — detours through hop-1
        const proxyOutbound = buildSingboxOutbound(config2, 'proxy', 'hop-1');
        if (config2.protocol === 'vless' && !proxyOutbound.packet_encoding) {
            proxyOutbound.packet_encoding = 'xudp';
        }

        // Map log level for Sing-box
        const sbLogLevel = logLevel === 'none' ? 'info' : (logLevel === 'warning' ? 'warn' : logLevel);

        const singboxClientConfig = {
            log: {
                level: sbLogLevel
            },
            dns: {
                servers: [
                    {
                        address: dnsServer,
                        detour: 'proxy',
                        tag: 'dns-remote'
                    },
                    {
                        address: '1.1.1.1',
                        detour: 'direct',
                        tag: 'dns-direct'
                    }
                ],
                rules: [
                    {
                        outbound: 'any',
                        server: 'dns-direct'
                    }
                ]
            },
            inbounds: [
                {
                    listen: '127.0.0.1',
                    listen_port: 2080,
                    sniff: true,
                    tag: 'mixed-in',
                    type: 'mixed'
                }
            ],
            outbounds: [
                hop1Outbound,
                proxyOutbound,
                {
                    tag: 'direct',
                    type: 'direct'
                },
                {
                    tag: 'dns-out',
                    type: 'dns'
                }
            ],
            route: {
                auto_detect_interface: true,
                final: 'proxy',
                rules: [
                    {
                        outbound: 'dns-out',
                        protocol: 'dns'
                    }
                ]
            }
        };

        return { config: singboxClientConfig, remark };
    }

    // ===== Nekobox Config Generator (Android Optimized) =====
    function generateNekoboxConfig(config1, config2) {
        const dnsServer = document.getElementById('dns-server').value;
        const logLevel = document.getElementById('log-level').value;

        const remark = `🔗 NEKOBOX: ${config1.protocol.toUpperCase()} → ${config2.protocol.toUpperCase()} | ${config2.server}:${config2.port}`;

        // Build hop-1 outbound (config1)
        const hop1Outbound = buildSingboxOutbound(config1, 'hop-1', null);
        if (config1.protocol === 'vless' && !hop1Outbound.packet_encoding) {
            hop1Outbound.packet_encoding = 'xudp';
        }

        // Build proxy outbound (config2) — detours through hop-1
        const proxyOutbound = buildSingboxOutbound(config2, 'proxy', 'hop-1');
        if (config2.protocol === 'vless' && !proxyOutbound.packet_encoding) {
            proxyOutbound.packet_encoding = 'xudp';
        }

        // Map log level for Sing-box
        const sbLogLevel = logLevel === 'none' ? 'info' : (logLevel === 'warning' ? 'warn' : logLevel);

        const nekoboxConfig = {
            log: {
                level: sbLogLevel
            },
            dns: {
                servers: [
                    {
                        tag: 'dns-remote',
                        address: dnsServer,
                        detour: 'proxy'
                    },
                    {
                        tag: 'dns-direct',
                        address: '1.1.1.1',
                        detour: 'direct'
                    }
                ],
                rules: [
                    {
                        outbound: 'any',
                        server: 'dns-direct'
                    }
                ]
            },
            inbounds: [
                {
                    type: 'tun',
                    tag: 'tun-in',
                    interface_name: 'tun0',
                    inet4_address: '172.19.0.1/30',
                    auto_route: true,
                    strict_route: true,
                    stack: 'system',
                    sniff: true,
                    sniff_override_destination: false
                }
            ],
            outbounds: [
                hop1Outbound,
                proxyOutbound,
                {
                    type: 'direct',
                    tag: 'direct'
                },
                {
                    type: 'dns',
                    tag: 'dns-out'
                }
            ],
            route: {
                auto_detect_interface: true,
                final: 'proxy',
                rules: [
                    {
                        protocol: 'dns',
                        outbound: 'dns-out'
                    }
                ]
            }
        };

        return { config: nekoboxConfig, remark };
    }

    function buildSingboxOutbound(params, tag, detourTag) {
        const outbound = {
            tag: tag,
            type: params.protocol === 'shadowsocks' ? 'shadowsocks' : params.protocol
        };

        // If this is a chain outbound, set detour
        if (detourTag) {
            outbound.detour = detourTag;
        }

        outbound.server = params.server;
        outbound.server_port = params.port;

        // Protocol-specific settings
        switch (params.protocol) {
            case 'vless':
                outbound.uuid = params.uuid;
                outbound.packet_encoding = '';
                outbound.network = 'tcp';
                if (params.flow) outbound.flow = params.flow;
                break;

            case 'vmess':
                outbound.uuid = params.uuid;
                outbound.security = 'auto';
                outbound.alter_id = params.aid || 0;
                outbound.network = 'tcp';
                break;

            case 'trojan':
                outbound.password = params.password;
                outbound.network = 'tcp';
                break;

            case 'shadowsocks':
                outbound.method = params.method;
                outbound.password = params.password;
                outbound.network = 'tcp';
                break;

            case 'socks':
                outbound.version = '5';
                outbound.network = 'tcp';
                // Auth credentials are only emitted when both username and
                // password are present, same as the Xray builder above.
                // A user-only credential would produce a broken outbound.
                if (params.user && params.pass) {
                    outbound.username = params.user;
                    outbound.password = params.pass;
                }
                break;

            case 'http':
                // Same rule as socks above: both username and password required.
                if (params.user && params.pass) {
                    outbound.username = params.user;
                    outbound.password = params.pass;
                }
                break;

            case 'ssh':
                outbound.type = 'ssh';
                outbound.user = params.user || 'root';
                outbound.password = params.password;
                // SSH has no TLS/transport, return early
                return outbound;

            default:
                return outbound;
        }

        // TLS settings
        const security = params.security || 'none';
        if (security === 'tls' || security === 'reality') {
            const tls = {
                enabled: true,
                server_name: params.sni || params.host || params.server
            };

            if (params.allowInsecure) tls.insecure = true;

            // ALPN
            if (params.alpn) {
                const alpnList = params.alpn.split(',').filter(v => v && v !== 'h2');
                if (alpnList.length) tls.alpn = alpnList;
            }

            // uTLS fingerprint
            if (params.fp) {
                tls.utls = {
                    enabled: true,
                    fingerprint: params.fp
                };
            }

            // Reality
            if (security === 'reality' && params.pbk) {
                tls.reality = {
                    enabled: true,
                    public_key: params.pbk,
                    short_id: params.sid || ''
                };
            }

            // ECH — param format: "query_server_name+dns_server" e.g. "workers.dev+udp://8.8.8.8"
            if (params.ech) {
                const echQueryServer = params.ech.split('+')[0];
                tls.record_fragment = false;
                tls.ech = {
                    enabled: true,
                    query_server_name: echQueryServer || params.sni || params.server
                };
            }

            outbound.tls = tls;
        }

        // Transport settings
        const transportType = params.type || 'tcp';
        switch (transportType) {
            case 'ws': {
                const wsTransport = {
                    type: 'ws',
                    path: (params.path || '/').split('?ed=')[0],
                    headers: {}
                };
                if (params.host) wsTransport.headers.Host = params.host;

                // Early data from ?ed= in path
                const edMatch = (params.path || '').match(/[?&]ed=(\d+)/);
                if (edMatch) {
                    wsTransport.max_early_data = parseInt(edMatch[1]);
                    wsTransport.early_data_header_name = 'Sec-WebSocket-Protocol';
                }
                outbound.transport = wsTransport;
                break;
            }

            case 'grpc': {
                outbound.transport = {
                    type: 'grpc',
                    service_name: params.serviceName || ''
                };
                break;
            }

            case 'httpupgrade': {
                outbound.transport = {
                    type: 'httpupgrade',
                    host: params.host,
                    path: (params.path || '/').split('?ed=')[0]
                };
                break;
            }

            case 'tcp': {
                if (params.headerType === 'http') {
                    outbound.transport = {
                        type: 'http',
                        host: params.host ? params.host.split(',') : undefined,
                        path: params.path || '/',
                        method: 'GET',
                        headers: {
                            'Connection': ['keep-alive'],
                            'Content-Type': ['application/octet-stream']
                        }
                    };
                }
                break;
            }

            case 'raw': {
                // raw = tcp without header in Sing-box
                break;
            }
        }

        // Enable TCP fast open if available
        if (params.tfo) outbound.tcp_fast_open = true;

        return outbound;
    }

    // ===== UI Render Helpers =====
    function renderParsedInfo(params, container) {
        if (!params || params.error) {
            container.innerHTML = params
                ? `<div class="error-msg">⚠️ ${params.error}</div>`
                : '';
            return;
        }

        if (Array.isArray(params)) {
            if (params.length === 0) {
                container.innerHTML = '';
                return;
            }
            if (params.length === 1) {
                renderParsedInfo(params[0], container);
                return;
            }

            const rows = [];
            rows.push(['Loaded Configs', `Found ${params.length} URLs`]);
            params.forEach((cfg, i) => {
                const label = `#${i + 1} ${cfg.protocol ? cfg.protocol.toUpperCase() : ''}`;
                const val = `${cfg.server || ''}:${cfg.port || ''}${cfg.remark ? ' (' + truncateStr(cfg.remark, 30) + ')' : ''}`;
                rows.push([label, val]);
            });

            container.innerHTML = rows.map(([label, value]) =>
                `<div class="info-row">
                    <span class="info-label">${label}</span>
                    <span class="info-value">${escapeHtml(String(value))}</span>
                </div>`
            ).join('');
            return;
        }

        const rows = [];
        rows.push(['Protocol', params.protocol.toUpperCase()]);
        rows.push(['Server', params.server]);
        rows.push(['Port', params.port]);

        if (params.uuid) rows.push(['UUID', params.uuid]);
        const passVal = params.password || params.pass;
        if (passVal) rows.push(['Password', maskString(passVal)]);
        if (params.method) rows.push(['Method', params.method]);
        if (params.user) rows.push(['User', params.user]);
        if (params.type && params.type !== 'tcp') rows.push(['Transport', params.type]);
        if (params.security && params.security !== 'none') rows.push(['Security', params.security]);
        if (params.sni) rows.push(['SNI', params.sni]);
        if (params.host) rows.push(['Host', params.host]);
        if (params.path) rows.push(['Path', truncateStr(params.path, 50)]);
        if (params.ech) rows.push(['ECH', '✅ Enabled']);
        if (params.allowInsecure) rows.push(['Insecure', '⚠️ Allowed']);
        if (params.remark) rows.push(['Remark', params.remark]);

        container.innerHTML = rows.map(([label, value]) =>
            `<div class="info-row">
                <span class="info-label">${label}</span>
                <span class="info-value">${escapeHtml(String(value))}</span>
            </div>`
        ).join('');
    }

    function maskString(str) {
        if (!str || str.length <= 8) return str;
        return str.slice(0, 4) + '••••' + str.slice(-4);
    }

    function truncateStr(str, max) {
        if (!str || str.length <= max) return str;
        return str.slice(0, max) + '…';
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function getProtocolColor(protocol) {
        const colors = {
            vless: '#7c5cff',
            vmess: '#5c8cff',
            trojan: '#f05050',
            shadowsocks: '#3cd4f0',
            socks: '#4cdf86',
            http: '#f0c040',
            ssh: '#ff8c42'
        };
        return colors[protocol] || '#9090b0';
    }

    function updateProtocolTag(tag, protocol) {
        if (protocol && !protocol.error) {
            tag.textContent = protocol.protocol.toUpperCase();
            tag.classList.add('active');
            tag.style.color = getProtocolColor(protocol.protocol);
            tag.style.borderColor = getProtocolColor(protocol.protocol) + '4d';
            tag.style.background = getProtocolColor(protocol.protocol) + '1a';
        } else {
            tag.textContent = '—';
            tag.classList.remove('active');
            tag.style.color = '';
            tag.style.borderColor = '';
            tag.style.background = '';
        }
    }

    // ===== JSON Syntax Highlighting =====
    function highlightJSON(json) {
        const str = JSON.stringify(json, null, 2);
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"([^"]+)"(?=\s*:)/g, '<span class="json-key">"$1"</span>')
            .replace(/:\s*"([^"]*)"/g, ': <span class="json-string">"$1"</span>')
            .replace(/:\s*(\d+\.?\d*)/g, ': <span class="json-number">$1</span>')
            .replace(/:\s*(true|false)/g, ': <span class="json-boolean">$1</span>')
            .replace(/:\s*(null)/g, ': <span class="json-null">$1</span>')
            .replace(/([{}[\]])/g, '<span class="json-brace">$1</span>');
    }

    // ===== Event Handlers =====
    function onInputChange(inputEl, parsedContainer, protocolTag, card, isConfig1) {
        let parsed;
        if (isConfig1 && sshMode1) {
            parsed = parseSSH(1);
        } else if (!isConfig1 && sshMode2) {
            parsed = parseSSH(2);
        } else {
            const val = inputEl.value.trim();
            parsed = val ? parseProxyURL(val) : null;
        }

        let singleConfig = null;
        if (Array.isArray(parsed)) {
            singleConfig = parsed[0];
        } else if (parsed && !parsed.error) {
            singleConfig = parsed;
        }

        if (isConfig1) {
            parsedConfig1 = singleConfig;
        } else {
            parsedConfig2 = singleConfig;
        }

        renderParsedInfo(parsed, parsedContainer);
        updateProtocolTag(protocolTag, singleConfig || (parsed && !Array.isArray(parsed) ? parsed : null));

        // For SSH mode, we also consider the card valid if server is filled
        card.classList.remove('valid', 'invalid');
        if (isConfig1 && sshMode1) {
            const server = document.getElementById('ssh-server1').value.trim();
            if (server && parsed) {
                card.classList.add(parsed.error ? 'invalid' : 'valid');
            }
        } else if (!isConfig1 && sshMode2) {
            const server = document.getElementById('ssh-server2').value.trim();
            if (server && parsed) {
                card.classList.add(parsed.error ? 'invalid' : 'valid');
            }
        } else {
            const val = inputEl.value.trim();
            if (val && (singleConfig || (parsed && !parsed.error))) {
                card.classList.add('valid');
            } else if (val) {
                card.classList.add('invalid');
            }
        }

        if (isConfig1 && parsedConfig1) {
            flowProxyLabel.textContent = `${parsedConfig1.protocol.toUpperCase()} ${parsedConfig1.server}`;
        } else if (isConfig1) {
            flowProxyLabel.textContent = 'Config 1';
        }

        if (!isConfig1 && parsedConfig2) {
            flowChainLabel.textContent = `${parsedConfig2.protocol.toUpperCase()} ${parsedConfig2.server}`;
        } else if (!isConfig1) {
            flowChainLabel.textContent = 'Config 2';
        }

        updateGenerateButton();
    }

    function updateGenerateButton() {
        const enabled = parsedConfig1 && parsedConfig2;
        btnGenerate.disabled = !enabled;
        generateHint.textContent = enabled
            ? 'Ready to generate!'
            : (!parsedConfig1 && !parsedConfig2)
                ? 'Paste both configs above to enable'
                : !parsedConfig1
                    ? 'Config 1 is missing or invalid'
                    : 'Config 2 is missing or invalid';
        generateHint.style.color = enabled ? '#4cdf86' : '';
    }

    function onGenerate() {
        if (!parsedConfig1 || !parsedConfig2) return;

        const hasSSH = parsedConfig1.protocol === 'ssh' || parsedConfig2.protocol === 'ssh';

        // Handle tabs visibility for SSH
        if (hasSSH) {
            tabXray.classList.add('disabled');
            tabXray.title = 'SSH is not supported by Xray';
            switchTab('singbox');
        } else {
            tabXray.classList.remove('disabled');
            tabXray.title = '';
        }

        // Generate Xray config (skip if SSH is involved)
        if (!hasSSH) {
            const xrayResult = generateFullConfig(parsedConfig1, parsedConfig2);
            if (!xrayResult) {
                outputSection.style.display = 'none';
                return;
            }
            outputRemarkXray.textContent = xrayResult.remark;
            outputJsonXray.innerHTML = highlightJSON(xrayResult.config);
        } else {
            outputRemarkXray.textContent = '';
            outputJsonXray.innerHTML = '<span style="color:#ff8c42">⚠️ SSH protocol is only supported by Sing-box. Xray config is not available.</span>';
        }

        // Generate Sing-box config
        const singboxResult = generateSingboxConfig(parsedConfig1, parsedConfig2);
        if (singboxResult) {
            outputRemarkSingbox.textContent = singboxResult.remark;
            outputJsonSingbox.innerHTML = highlightJSON(singboxResult.config);
        }

        // Generate Nekoray config
        const singboxClientResult = generateSingboxClientConfig(parsedConfig1, parsedConfig2);
        if (singboxClientResult) {
            outputRemarkSingboxClient.textContent = singboxClientResult.remark;
            outputJsonSingboxClient.innerHTML = highlightJSON(singboxClientResult.config);
        }

        // Generate Nekobox config
        const nekoboxResult = generateNekoboxConfig(parsedConfig1, parsedConfig2);
        if (nekoboxResult) {
            outputRemarkNekobox.textContent = nekoboxResult.remark;
            outputJsonNekobox.innerHTML = highlightJSON(nekoboxResult.config);
        }

        outputSection.style.display = 'block';
        outputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function doCopy(btn, configGenerator) {
        if (!parsedConfig1 || !parsedConfig2) return;
        const result = configGenerator(parsedConfig1, parsedConfig2);
        if (!result) return;

        const text = JSON.stringify(result.config, null, 2);
        navigator.clipboard.writeText(text).then(() => {
            btn.classList.add('copied');
            btn.innerHTML = '<span class="copy-icon">✅</span> Copied!';
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.innerHTML = '<span class="copy-icon">📋</span> Copy';
            }, 2000);
        });
    }

    function doDownload(configGenerator, prefix) {
        if (!parsedConfig1 || !parsedConfig2) return;
        const result = configGenerator(parsedConfig1, parsedConfig2);
        if (!result) return;

        const text = JSON.stringify(result.config, null, 2);
        const blob = new Blob([text], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${prefix}-${parsedConfig1.protocol}-${parsedConfig2.protocol}-${parsedConfig2.server}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ===== Main Tab switching =====
    function switchMainTab(viewName) {
        mainTabs.forEach(t => {
            t.classList.toggle('active', t.dataset.view === viewName);
        });
        viewChain.style.display = viewName === 'chain' ? '' : 'none';
        viewEnhancer.style.display = viewName === 'enhancer' ? '' : 'none';
        document.querySelectorAll('.protocol-badges .badge').forEach(badge => {
            const show = viewName === 'chain' || ['vless', 'trojan'].includes(badge.dataset.protocol);
            badge.style.display = show ? '' : 'none';
        });
    }

    mainTabs.forEach(tab => {
        tab.addEventListener('click', () => switchMainTab(tab.dataset.view));
    });

    // Apply badge visibility for the initial view (enhancer is active by default)
    switchMainTab('enhancer');

    // ===== Tab switching =====
    function switchTab(tabName) {
        [tabXray, tabSingbox].forEach(t => t.classList.remove('active'));
        [panelXray, panelSingbox].forEach(p => p.classList.remove('active'));

        if (tabName === 'xray') {
            tabXray.classList.add('active');
            panelXray.classList.add('active');
        } else {
            tabSingbox.classList.add('active');
            panelSingbox.classList.add('active');
        }
    }

    function switchSubTab(subTabName) {
        const subTabs = document.querySelectorAll('.sub-tab');
        const subPanels = document.querySelectorAll('.sub-panel');

        subTabs.forEach(t => {
            if (t.dataset.subtab === subTabName) {
                t.classList.add('active');
            } else {
                t.classList.remove('active');
            }
        });

        subPanels.forEach(p => {
            if (p.id === `subpanel-${subTabName}`) {
                p.classList.add('active');
            } else {
                p.classList.remove('active');
            }
        });
    }

    // ===== Wire Events =====
    config1Input.addEventListener('input', () =>
        onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true));
    config2Input.addEventListener('input', () =>
        onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false));
    config1Input.addEventListener('paste', () =>
        setTimeout(() => onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true), 50));
    config2Input.addEventListener('paste', () =>
        setTimeout(() => onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false), 50));

    clear1.addEventListener('click', () => {
        config1Input.value = '';
        onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true);
    });
    clear2.addEventListener('click', () => {
        config2Input.value = '';
        onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false);
    });

    btnGenerate.addEventListener('click', onGenerate);

    // Xray copy/download
    btnCopyXray.addEventListener('click', () => doCopy(btnCopyXray, generateFullConfig));
    btnDownloadXray.addEventListener('click', () => doDownload(generateFullConfig, 'xray-chain'));

    // Sing-box copy/download
    btnCopySingbox.addEventListener('click', () => doCopy(btnCopySingbox, generateSingboxConfig));
    btnDownloadSingbox.addEventListener('click', () => doDownload(generateSingboxConfig, 'singbox-chain'));

    // Nekoray copy/download
    btnCopySingboxClient.addEventListener('click', () => doCopy(btnCopySingboxClient, generateSingboxClientConfig));
    btnDownloadSingboxClient.addEventListener('click', () => doDownload(generateSingboxClientConfig, 'nekoray-chain'));

    // Nekobox copy/download
    btnCopyNekobox.addEventListener('click', () => doCopy(btnCopyNekobox, generateNekoboxConfig));
    btnDownloadNekobox.addEventListener('click', () => doDownload(generateNekoboxConfig, 'nekobox-chain'));

    // Tab switching
    tabXray.addEventListener('click', () => {
        if (!tabXray.classList.contains('disabled')) switchTab('xray');
    });
    tabSingbox.addEventListener('click', () => switchTab('singbox'));

    // Sub-tab switching
    document.querySelectorAll('.sub-tab').forEach(btn => {
        btn.addEventListener('click', () => {
            switchSubTab(btn.dataset.subtab);
        });
    });

    // ===== SSH Toggle & Form Events =====
    function toggleSSHMode(configNum) {
        const isConfig1 = configNum === 1;
        const toggle = isConfig1 ? sshToggle1 : sshToggle2;
        const sshForm = isConfig1 ? sshForm1 : sshForm2;
        const urlGroup = isConfig1 ? urlInputGroup1 : urlInputGroup2;
        const inputEl = isConfig1 ? config1Input : config2Input;
        const parsedContainer = isConfig1 ? parsed1 : parsed2;
        const protocolTag = isConfig1 ? protocol1Tag : protocol2Tag;
        const card = isConfig1 ? config1Card : config2Card;

        if (isConfig1) {
            sshMode1 = !sshMode1;
        } else {
            sshMode2 = !sshMode2;
        }

        const active = isConfig1 ? sshMode1 : sshMode2;
        toggle.classList.toggle('active', active);

        if (active) {
            urlGroup.style.display = 'none';
            sshForm.style.display = 'block';
            inputEl.value = '';
        } else {
            urlGroup.style.display = '';
            sshForm.style.display = 'none';
        }

        // Trigger re-parse
        onInputChange(inputEl, parsedContainer, protocolTag, card, isConfig1);
    }

    sshToggle1.addEventListener('click', () => toggleSSHMode(1));
    sshToggle2.addEventListener('click', () => toggleSSHMode(2));

    // SSH field input events
    ['ssh-server1', 'ssh-port1', 'ssh-user1', 'ssh-pass1'].forEach(id => {
        document.getElementById(id).addEventListener('input', () => {
            if (sshMode1) onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true);
        });
    });
    ['ssh-server2', 'ssh-port2', 'ssh-user2', 'ssh-pass2'].forEach(id => {
        document.getElementById(id).addEventListener('input', () => {
            if (sshMode2) onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false);
        });
    });

    // SSH clear buttons
    document.getElementById('ssh-clear1').addEventListener('click', () => {
        ['ssh-server1', 'ssh-user1', 'ssh-pass1'].forEach(id => document.getElementById(id).value = '');
        document.getElementById('ssh-port1').value = '22';
        onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true);
    });
    document.getElementById('ssh-clear2').addEventListener('click', () => {
        ['ssh-server2', 'ssh-user2', 'ssh-pass2'].forEach(id => document.getElementById(id).value = '');
        document.getElementById('ssh-port2').value = '22';
        onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false);
    });

    // SSH password show/hide toggle
    document.querySelectorAll('.ssh-pass-toggle').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const target = document.getElementById(btn.dataset.target);
            if (target.type === 'password') {
                target.type = 'text';
                btn.textContent = '🔒';
            } else {
                target.type = 'password';
                btn.textContent = '👁️';
            }
        });
    });

    // ===== Enhancer events =====
    // Fragment presets — switching only overwrites the textarea on explicit
    // selector change, so manual edits are always preserved.
    const FRAGMENT_PRESETS = {
        v1: '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}',
        v2: '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}'
    };
    if (enhancerFmPreset) {
        enhancerFmPreset.addEventListener('change', () => {
            const preset = FRAGMENT_PRESETS[enhancerFmPreset.value];
            if (preset !== undefined) {
                enhancerFm.value = preset;
            }
        });
    }
    enhancerInput.addEventListener('input', onEnhancerInput);
    enhancerInput.addEventListener('paste', () => setTimeout(onEnhancerInput, 50));
    enhancerClear.addEventListener('click', () => {
        enhancerInput.value = '';
        onEnhancerInput();
    });
    btnEnhance.addEventListener('click', onEnhance);
    btnCopyEnhancer.addEventListener('click', () => {
        const text = enhancerOutputUrl.textContent;
        if (!text) return;
        navigator.clipboard.writeText(text).then(() => {
            btnCopyEnhancer.classList.add('copied');
            btnCopyEnhancer.innerHTML = '<span class="copy-icon">✅</span> Copied!';
            setTimeout(() => {
                btnCopyEnhancer.classList.remove('copied');
                btnCopyEnhancer.innerHTML = '<span class="copy-icon">📋</span> Copy';
            }, 2000);
        });
    });
})();
