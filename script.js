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
    const viewSub = document.getElementById('view-sub');
    const viewEch = document.getElementById('view-ech');

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

    // ECH tab elements (own card — not shared with other tabs)
    const echInput = document.getElementById('ech-input');
    const echClear = document.getElementById('ech-clear');
    const echParsed = document.getElementById('ech-parsed');
    const echProtocolTag = document.getElementById('ech-protocol-tag');
    const echServer = document.getElementById('ech-server');
    const echFp = document.getElementById('ech-fp');
    const echPreset = document.getElementById('ech-preset');
    const echText = document.getElementById('ech-text');
    const btnEchEnhance = document.getElementById('btn-ech-enhance');
    const echHint = document.getElementById('ech-hint');
    const echOutputSection = document.getElementById('ech-output-section');
    const echOutputUrl = document.getElementById('ech-output-url');
    const echOutputRemark = document.getElementById('ech-output-remark');
    const btnCopyEch = document.getElementById('btn-copy-ech');
    const echCard = document.getElementById('ech-card');

    // ECH subscription input (paste contents or fetch a link — shared output)
    const echSubCard = document.getElementById('ech-sub-card');
    const echSubInput = document.getElementById('ech-sub-input');
    const echSubClear = document.getElementById('ech-sub-clear');
    const echSubParsed = document.getElementById('ech-sub-parsed');
    const btnEchSub = document.getElementById('btn-ech-sub');
    const echSubHint = document.getElementById('ech-sub-hint');
    const btnEchOpenSub = document.getElementById('btn-ech-open-sub');
    const btnDownloadEch = document.getElementById('btn-download-ech');
    const btnDownloadEchB64 = document.getElementById('btn-download-ech-b64');
    let echOutputList = [];
    let echSubRaw = [];
    let echSubBusy = false;
    let echLastSource = '';
    let echSubProgressTimer = null;

    // Throttled progress text (150 ms), mirroring the Subscription tab — the
    // fetch callback fires per chunk, which is too noisy for large bodies.
    function onEchSubProgress(loaded, total) {
        if (echSubProgressTimer) return;
        echSubProgressTimer = setTimeout(() => {
            echSubProgressTimer = null;
            if (!echSubBusy) return;
            const kb = Math.round(loaded / 1024);
            echSubHint.textContent = total
                ? 'Fetching… ' + kb + ' / ' + Math.round(total / 1024) + ' KB'
                : 'Fetching… ' + kb + ' KB';
        }, 150);
    }

    let parsedConfig1 = null;
    let parsedConfig2 = null;
    let sshMode1 = false;
    let sshMode2 = false;
    let lastAutoServer = '';
    let lastAutoEchServer = '';

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

    // ECH query server: only the DNS-query form "domain+dns-server"
    // (e.g. "cloudflare-ech.com+https://dns.alidns.com/dns-query" or
    // "cloudflare-ech.com+udp://1.1.1.1") carries a queryable domain.
    // A raw base64 ECHConfigList can itself contain '+' (base64 alphabet),
    // so it must not be split — return '' so callers fall back to sni/server.
    // Split on whitespace too: a badly-encoded external link may carry a
    // literal '+' which URLSearchParams decodes to a space.
    function getEchQueryServer(ech) {
        if (!ech || !ech.includes('://')) return '';
        const head = ech.split(/[+\s]/)[0].trim();
        // A bare resolver with no domain part ("udp://1.1.1.1" or a lone
        // "https://..." URL from a mistyped field) is not a queryable name —
        // callers fall back to sni/server instead of emitting a URL there.
        if (!head || head.includes('://')) return '';
        return head;
    }

    // Default DNS appended to a bare ECH domain, BPB-style:
    // "cloudflare-ech.com" becomes "cloudflare-ech.com+udp://8.8.8.8".
    const ECH_DNS_DEFAULT = 'udp://8.8.8.8';

    // Bare ECH domain (just a hostname, no resolver part). Dots never appear
    // in standard/base64url alphabets, so a dot-containing value without
    // '://', '+', '/' or '=' cannot be a base64 ECHConfigList.
    function isBareEchDomain(value) {
        if (!value || value.includes('://')) return false;
        if (/[\s+=/]/.test(value)) return false;
        return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value);
    }

    // Normalize the enhancer textarea value before writing the URL param:
    // bare domains are completed with the default DNS, full DNS-query forms
    // and raw base64 pass through untouched, empty stays empty (skip ech).
    function normalizeEchInput(raw) {
        const value = (raw || '').trim();
        if (!value) return '';
        if (isBareEchDomain(value)) return value + '+' + ECH_DNS_DEFAULT;
        return value;
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

    function enhanceURL(raw, opts) {
        const url = raw.trim();
        if (!url) return { error: 'No URL provided' };
        // Case-insensitive on purpose — parseProxyURLSingle() accepts VLESS://
        // as well, and the bulk path would otherwise count those as "skipped".
        const scheme = url.slice(0, url.indexOf('://')).toLowerCase();
        if (scheme !== 'vless' && scheme !== 'trojan') {
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

        // Server override — auto-filled from URL, user-editable, empty keeps original.
        // opts.ignoreServer skips it: a subscription holds many servers, so rewriting
        // every entry to one address would break the whole list.
        const server = (opts && opts.ignoreServer) ? '' : enhancerServer.value.trim();
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

    // ===== ECH Enhancer (own tab — fp + ech only) =====

    function enhanceEchURL(raw, opts) {
        const url = raw.trim();
        if (!url) return { error: 'No URL provided' };
        // Case-insensitive on purpose — parseProxyURLSingle() accepts VLESS://
        // as well, and the bulk path would otherwise count those as "skipped".
        const scheme = url.slice(0, url.indexOf('://')).toLowerCase();
        if (scheme !== 'vless' && scheme !== 'trojan') {
            return { error: 'Only VLESS and Trojan URLs are supported' };
        }

        let u;
        try {
            u = new URL(url);
        } catch (e) {
            return { error: 'Failed to parse URL: ' + e.message };
        }

        const params = u.searchParams;
        // Missing security means plaintext ('none') — Trojan links are not
        // always TLS (e.g. port-80 ws links with no security param), so never
        // assume 'tls' here; that would inject ech into a plaintext config.
        const security = params.get('security') || 'none';

        // Server override — auto-filled from URL, user-editable, empty keeps original.
        // opts.ignoreServer skips it for bulk input: a subscription holds many
        // servers, so rewriting every entry to one address would break the list.
        const server = (opts && opts.ignoreServer) ? '' : echServer.value.trim();
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

        // Fingerprint — applied when set; 'none'/empty removes an existing value
        // so "clear to skip" also strips a previously-enhanced URL.
        const fp = echFp.value.trim();
        if (fp && fp !== 'none') {
            params.set('fp', fp);
        } else {
            params.delete('fp');
        }

        // ECH config list — only meaningful with TLS. A bare domain
        // ("cloudflare-ech.com") is completed with the default DNS, BPB-style;
        // URLSearchParams serializes the '+' separator as %2B, which is what
        // Xray expects. Empty removes an existing value ("clear to skip").
        if (security === 'tls') {
            const ech = normalizeEchInput(echText.value);
            if (ech) {
                params.set('ech', ech);
            } else {
                params.delete('ech');
            }
        }

        // URLSearchParams encodes spaces as '+', but v2ray-style clients use '%20'
        u.search = u.search.replace(/\+/g, '%20');

        return { url: u.toString() };
    }

    function onEchInput() {
        const val = echInput.value.trim();
        const lines = extractLines(val);

        // The output box is shared with the subscription input — any edit here
        // invalidates whatever is shown, whichever input produced it.
        echOutputSection.style.display = 'none';
        echOutputUrl.textContent = '';
        echOutputRemark.textContent = '';
        echLastSource = '';
        echOutputList = [];
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
        if (parsedList.length === 1) {
            const firstServer = parsedList[0].server || '';
            const current = echServer.value.trim();
            if (!current || current === lastAutoEchServer || current === firstServer) {
                echServer.value = firstServer;
                lastAutoEchServer = firstServer;
            }
        } else if (parsedList.length > 1) {
            const current = echServer.value.trim();
            if (!current || current === lastAutoEchServer) {
                echServer.value = '';
                lastAutoEchServer = '';
            }
        } else if (!echServer.value.trim()) {
            lastAutoEchServer = '';
        }

        if (lines.length > 0) {
            if (parsedList.length > 0) {
                renderParsedInfo(parsedList.length === 1 ? parsedList[0] : parsedList, echParsed);
                const protocols = Array.from(new Set(parsedList.map(p => p.protocol)));
                if (protocols.length === 1) {
                    updateProtocolTag(echProtocolTag, parsedList[0]);
                } else {
                    echProtocolTag.textContent = 'MULTI';
                    echProtocolTag.classList.add('active');
                    echProtocolTag.style.color = '#7c5cff';
                    echProtocolTag.style.borderColor = '#7c5cff4d';
                    echProtocolTag.style.background = '#7c5cff1a';
                }
            } else {
                renderParsedInfo({
                    error: unsupportedCount > 0
                        ? 'Only VLESS and Trojan URLs are supported'
                        : 'Failed to parse URL'
                }, echParsed);
                updateProtocolTag(echProtocolTag, null);
            }
        } else {
            renderParsedInfo(null, echParsed);
            updateProtocolTag(echProtocolTag, null);
        }

        echCard.classList.remove('valid', 'invalid');
        if (lines.length > 0 && parsedList.length > 0) {
            echCard.classList.add('valid');
        } else if (lines.length > 0) {
            echCard.classList.add('invalid');
        }

        const count = parsedList.length;
        btnEchEnhance.disabled = count === 0;
        btnEchEnhance.innerHTML = `<span class="btn-icon">✨</span> Enhance ${count > 1 ? count + ' URLs' : 'URL'}`;
        echHint.textContent = count > 0
            ? `Ready to enhance ${count} URL${count > 1 ? 's' : ''}!`
            : 'Paste VLESS or Trojan URL(s) above to enable';
        echHint.style.color = count > 0 ? '#4cdf86' : '';
    }

    function onEchEnhance() {
        const val = echInput.value.trim();
        const lines = extractLines(val);
        if (lines.length === 0) {
            echOutputSection.style.display = 'none';
            return;
        }

        const enhancedUrls = [];
        let firstEnhanced = null;
        lines.forEach(line => {
            const p = parseProxyURLSingle(line);
            if (p && !p.error && (p.protocol === 'vless' || p.protocol === 'trojan')) {
                const res = enhanceEchURL(line);
                if (res && res.url) {
                    if (!firstEnhanced) firstEnhanced = p;
                    enhancedUrls.push(res.url);
                }
            }
        });

        if (enhancedUrls.length === 0) {
            echOutputSection.style.display = 'none';
            echOutputList = [];
            echHint.textContent = 'Could not enhance — check the URLs and the Server override';
            echHint.style.color = '#f05050';
            return;
        }

        const count = enhancedUrls.length;
        const firstParsed = firstEnhanced;
        // Show the post-override address: read it back from the enhanced URL
        // rather than the pre-enhance parse result.
        let remarkHost = firstParsed ? `${firstParsed.server}:${firstParsed.port}` : '';
        try {
            const firstOut = new URL(enhancedUrls[0]);
            if (firstOut.hostname) remarkHost = firstOut.host;
        } catch {
            // keep the pre-enhance values
        }
        const remark = count === 1
            ? (firstParsed && firstParsed.remark
                ? `✨ ${firstParsed.protocol.toUpperCase()} ${remarkHost} | enhanced`
                : '✨ Enhanced')
            : `✨ Enhanced ${count} URLs`;

        echOutputRemark.textContent = remark;
        echOutputUrl.textContent = enhancedUrls.join('\n\n');
        echOutputSection.style.display = 'block';
        echLastSource = 'url';
        echOutputList = enhancedUrls;
        echOutputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ===== ECH subscription input (link fetch or pasted contents, shared output) =====

    function setEchSubError(text) {
        echSubParsed.textContent = '';
        const err = document.createElement('div');
        err.className = 'error-msg';
        err.textContent = '⚠️ ' + text;
        echSubParsed.appendChild(err);
    }

    // Manual-fetch fallback for providers that block browser fetches (no CORS
    // headers): an "Open link" button + 3 steps, mirroring the Subscription tab.
    // Built with DOM APIs only (no innerHTML).
    function setEchSubCorsGuide(linkUrl) {
        const guide = document.createElement('div');
        guide.className = 'sub-guide';
        const title = document.createElement('div');
        title.textContent = 'Get the content manually — 3 quick steps:';
        const steps = document.createElement('ol');
        const first = document.createElement('li');
        first.textContent = 'Open your subscription link in a new tab: ';
        const openBtn = document.createElement('button');
        openBtn.type = 'button';
        openBtn.className = 'btn-subtle';
        openBtn.textContent = '↗ Open link';
        openBtn.addEventListener('click', () => openSubLink(linkUrl));
        first.appendChild(openBtn);
        const second = document.createElement('li');
        second.textContent = 'Select everything there and copy it (Ctrl+A, then Ctrl+C).';
        const third = document.createElement('li');
        third.textContent = 'Paste it into the subscription box above and press Fetch & Enhance Sub.';
        steps.append(first, second, third);
        guide.append(title, steps);
        echSubParsed.appendChild(guide);
    }

    // Enables the Open-link button exactly when the field holds a link.
    function syncEchOpenButton() {
        btnEchOpenSub.disabled = subValidate(echSubInput.value.trim()) !== 'link';
    }

    function onEchSubInput() {
        const raw = echSubInput.value.trim();
        // A fetch is in flight — typing must not re-enable the button (the
        // click would be swallowed by the busy guard in onEchSub anyway).
        if (echSubBusy) {
            btnEchSub.disabled = true;
            return;
        }
        echSubCard.classList.remove('valid', 'invalid');
        echSubRaw = [];

        // Any edit invalidates the previous result, whichever input produced it.
        echOutputSection.style.display = 'none';
        echOutputUrl.textContent = '';
        echOutputRemark.textContent = '';
        echSubParsed.textContent = '';
        echSubHint.style.color = '';
        echOutputList = [];

        if (!raw) {
            btnEchSub.disabled = true;
            btnEchOpenSub.disabled = true;
            echSubHint.textContent = 'Paste a subscription link — or its contents — above to enable';
            return;
        }

        const mode = subValidate(raw);
        if (mode === 'link' || mode === 'content') {
            echSubCard.classList.add('valid');
            btnEchSub.disabled = false;
            syncEchOpenButton();
            echSubHint.textContent = mode === 'link'
                ? 'Ready to fetch & enhance'
                : 'Ready to enhance pasted contents';
            echSubHint.style.color = '#4cdf86';
        } else if (mode === 'proxy') {
            echSubCard.classList.add('invalid');
            btnEchSub.disabled = true;
            btnEchOpenSub.disabled = true;
            echSubHint.textContent = 'That looks like an HTTP proxy address, not a subscription';
            setEchSubError('That looks like an HTTP proxy address, not a subscription link. Only VLESS and Trojan URLs can be enhanced — paste one of those, or a subscription link. If this is actually a subscription served at a bare address with no path, open it in a new tab and paste its contents here instead.');
        } else {
            echSubCard.classList.add('invalid');
            btnEchSub.disabled = true;
            btnEchOpenSub.disabled = true;
            echSubHint.textContent = 'Unrecognized input — paste a subscription link or its contents';
        }
    }

    function renderEchSubResults(configs, focus) {
        let enhanced = [];
        let skipped = 0;
        let invalid = 0;
        configs.forEach(line => {
            // Raw base64 container line (no scheme): when it decodes to config
            // lines, those twins are already separate entries below — skip it
            // silently instead of a phantom skip/invalid report.
            if (!SUB_SCHEME.test(line)) {
                const decoded = safeAtob(line.replace(/^\/\/.*$/, '').trim());
                if (decoded && extractLines(decoded).some(l => SUB_SCHEME.test(l))) return;
            }
            const p = parseProxyURLSingle(line);
            if (!p || p.error) {
                invalid++;
                return;
            }
            if (p.protocol !== 'vless' && p.protocol !== 'trojan') {
                skipped++;
                return;
            }
            const res = enhanceEchURL(line, { ignoreServer: true });
            if (res && res.url) {
                enhanced.push(res.url);
            } else if (line.includes('://')) {
                // The line parsed but could not be enhanced — unusable line.
                invalid++;
            }
            // Else: raw base64 line whose decoded twin was already counted —
            // ignored silently instead of a phantom skip/invalid report.
        });

        if (enhanced.length === 0) {
            echOutputSection.style.display = 'none';
            echOutputList = [];
            echSubHint.textContent = configs.length
                ? 'Found configs, but none were VLESS/Trojan with a usable URL'
                : 'No proxy configs found in the input';
            echSubHint.style.color = '#f0c040';
            echSubCard.classList.remove('valid');
            echSubCard.classList.add('invalid');
            setEchSubError(configs.length
                ? configs.length + ' config(s) found, but none could be enhanced — only VLESS and Trojan URLs are supported.'
                : 'No recognizable VLESS/Trojan configs in the input. Open the link in a new tab and paste its contents here.');
            return;
        }

        echSubParsed.textContent = '';
        echSubCard.classList.remove('invalid');
        echSubCard.classList.add('valid');

        const parts = ['✨ ' + enhanced.length + ' enhanced config(s)'];
        if (skipped) parts.push('skipped ' + skipped + ' non-VLESS/Trojan');
        if (invalid) parts.push('ignored ' + invalid + ' unparseable line(s)');
        echOutputRemark.textContent = parts.join(' · ');
        echOutputUrl.textContent = enhanced.join('\n');
        echOutputSection.style.display = 'block';
        echLastSource = 'sub';
        echOutputList = enhanced;
        if (focus) echOutputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        echSubHint.textContent = 'Done';
        echSubHint.style.color = '#4cdf86';
    }

    // Re-enhance stored subscription configs when the ECH options change,
    // without re-fetching. Only fires when the visible output came from the
    // subscription input — never clobbers URL-input results.
    let echSubRenderTimer = null;
    function scheduleEchSubRender() {
        if (echSubBusy || !echSubRaw.length || echLastSource !== 'sub') return;
        clearTimeout(echSubRenderTimer);
        echSubRenderTimer = setTimeout(() => {
            echSubRenderTimer = null;
            if (echSubBusy || !echSubRaw.length || echLastSource !== 'sub') return;
            renderEchSubResults(echSubRaw, false);
        }, 300);
    }

    async function onEchSub() {
        const raw = echSubInput.value.trim();
        if (!raw || echSubBusy) return;

        const mode = subValidate(raw);
        if (mode !== 'link' && mode !== 'content') {
            onEchSubInput();
            return;
        }

        // Pasted content: no fetch at all.
        if (mode === 'content') {
            echSubRaw = extractSubConfigs(raw);
            renderEchSubResults(echSubRaw, true);
            return;
        }

        echSubBusy = true;
        btnEchSub.disabled = true;
        btnEchOpenSub.disabled = true;
        echSubHint.textContent = 'Fetching…';
        echSubHint.style.color = '';
        echSubParsed.textContent = '';
        echSubCard.classList.remove('invalid');
        echOutputSection.style.display = 'none';
        echOutputUrl.textContent = '';
        echOutputRemark.textContent = '';
        echSubRaw = [];
        echOutputList = [];

        try {
            const body = await fetchSubBody(raw, onEchSubProgress);
            echSubBusy = false;
            if (echSubProgressTimer) {
                clearTimeout(echSubProgressTimer);
                echSubProgressTimer = null;
            }
            btnEchSub.disabled = false;
            // The field changed mid-fetch — drop the result, never render output
            // under input it no longer belongs to.
            if (echSubInput.value.trim() !== raw) {
                echSubRaw = [];
                onEchSubInput();
                echSubHint.textContent = 'Input changed during the fetch — fetch again';
                echSubHint.style.color = '#f0c040';
                return;
            }
            echSubRaw = extractSubConfigs(body);
            renderEchSubResults(echSubRaw, true);
            syncEchOpenButton();
        } catch (e) {
            echSubBusy = false;
            if (echSubProgressTimer) {
                clearTimeout(echSubProgressTimer);
                echSubProgressTimer = null;
            }
            btnEchSub.disabled = false;
            if (echSubInput.value.trim() !== raw) {
                echSubRaw = [];
                onEchSubInput();
                echSubHint.textContent = 'Input changed during the fetch — fetch again';
                echSubHint.style.color = '#f0c040';
                return;
            }
            echSubHint.textContent = 'Fetch failed';
            echSubHint.style.color = '#f05050';
            echSubCard.classList.remove('valid');
            echSubCard.classList.add('invalid');
            setEchSubError(subErrorText(e));
            syncEchOpenButton();
            if (subIsBlockedError(e) && (typeof navigator === 'undefined' || navigator.onLine !== false)) setEchSubCorsGuide(raw);
        }
    }

    // Accept a saved subscription file (.txt) dropped onto the ECH sub card.
    // Everything stays local: FileReader never uploads anything.
    function onEchSubDropError(text) {
        echOutputSection.style.display = 'none';
        echOutputUrl.textContent = '';
        echOutputRemark.textContent = '';
        // Re-validate whatever is actually in the field instead of assuming
        // the input needs fixing — the field may still hold a valid link.
        onEchSubInput();
        setEchSubError(text);
        echSubRaw = [];
        echOutputList = [];
    }
    function onEchSubDragOver(e) {
        e.preventDefault();
        echSubCard.classList.add('dragover');
    }
    function onEchSubDragLeave(e) {
        e.preventDefault();
        // dragleave also fires when moving between children of the card —
        // only clear the highlight when the pointer truly leaves it.
        if (e.relatedTarget && echSubCard.contains(e.relatedTarget)) return;
        echSubCard.classList.remove('dragover');
    }
    function onEchSubDrop(e) {
        e.preventDefault();
        echSubCard.classList.remove('dragover');
        const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
        if (!file) return;
        if (file.size > SUB_MAX_FILE_BYTES) {
            onEchSubDropError('That file is too large — drop a plain-text subscription file (.txt), usually a few hundred KB at most.');
            return;
        }
        const reader = new FileReader();
        reader.onload = () => {
            echSubInput.value = String(reader.result || '');
            onEchSubInput();
            echSubInput.focus();
        };
        reader.onerror = () => onEchSubDropError('Could not read that file.');
        reader.readAsText(file);
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
                const echDomain = getEchQueryServer(cfg.ech);
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
                const echQueryServer = getEchQueryServer(params.ech);
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
        // file:// / plain http have no async clipboard — a sync throw here
        // would bypass .then() entirely, so bail out quietly instead.
        if (!navigator.clipboard || !navigator.clipboard.writeText) return;
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

    // ===== Subscription Import =====

    const subUrl = document.getElementById('sub-url');
    const subClear = document.getElementById('sub-clear');
    const subParsed = document.getElementById('sub-parsed');
    const subProtocolTag = document.getElementById('sub-protocol-tag');
    const subCard = document.getElementById('sub-card');
    const btnSub = document.getElementById('btn-sub');
    const btnOpenSub = document.getElementById('btn-open-sub');
    const subHint = document.getElementById('sub-hint');
    const subOutputSection = document.getElementById('sub-output-section');
    const subOutputUrl = document.getElementById('sub-output-url');
    const subOutputRemark = document.getElementById('sub-output-remark');
    const btnCopySub = document.getElementById('btn-copy-sub');
    const btnDownloadSub = document.getElementById('btn-download-sub');
    const btnDownloadSubB64 = document.getElementById('btn-download-sub-b64');

    // Bodies can be several hundred KB and arrive slowly, so we abort on
    // silence rather than after a fixed total time.
    const SUB_IDLE_MS = 30000;
    // Backstop for a body that trickles forever without ever going silent.
    const SUB_TOTAL_MS = 5 * 60 * 1000;

    let subResults = [];
    let subRawConfigs = [];
    let subMode = 'link';
    let subBusy = false;
    // Two timers, not one: the progress throttle and the option debounce must
    // not cancel each other.
    let subProgressTimer = null;
    let subRenderTimer = null;

    // One scheme list for every branch of the bulk path, so a scheme added here
    // works in plain text, whole-blob base64 and per-line base64 alike.
    const SUB_SCHEME = /^(vless|vmess|trojan|ss|socks5?|tg):\/\//i;

    // Returns every proxy line found in a subscription body, whether it arrives
    // as plain text, as one base64 blob, or as a mix of plain lines and
    // per-line base64 blobs.
    function extractSubConfigs(body) {
        let text = (body || '').trim();
        if (!text) return [];

        const lines = extractLines(text);

        // Plain text list that also carries per-line base64 blobs: keep every
        // line, exactly as before, and append whatever the non-plain lines
        // decode to. Inputs without any base64 line return byte-identical
        // results to the old early-return.
        if (lines.some(l => SUB_SCHEME.test(l))) {
            const out = lines.slice();
            const seen = new Set(out);
            for (const line of lines) {
                if (SUB_SCHEME.test(line)) continue;
                const decoded = safeAtob(line.replace(/^\/\/.*$/, '').trim());
                if (!decoded) continue;
                for (const dl of extractLines(decoded)) {
                    if (SUB_SCHEME.test(dl) && !seen.has(dl)) {
                        seen.add(dl);
                        out.push(dl);
                    }
                }
            }
            return out;
        }

        // Base64 body: try the whole payload first (standard subscription format),
        // then line by line for providers that send a base64 blob per config.
        const whole = safeAtob(text.replace(/\s+/g, ''));
        if (whole) {
            const decodedLines = extractLines(whole);
            if (decodedLines.some(l => SUB_SCHEME.test(l))) {
                return decodedLines;
            }
        }

        // Last resort: some providers base64 each config on its own line. Only
        // decoded lines that actually hold a proxy scheme count — otherwise any
        // base64-looking word (an HTML file, a comment) becomes a "config".
        return extractLines(text)
            .map(l => safeAtob(l.replace(/^\/\/.*$/, '').trim()))
            .filter(Boolean)
            .flatMap(extractLines)
            .filter(l => SUB_SCHEME.test(l));
    }

    // Streams the response so a large body can arrive over a slow link without
    // hitting a fixed timeout; the connection is aborted after SUB_IDLE_MS of
    // silence, with SUB_TOTAL_MS as a backstop so a trickle that never goes
    // silent for a full 30s still ends. onProgress(receivedBytes, totalBytes)
    // drives the status line.
    async function fetchTextWithProgress(url, onProgress) {
        const ctrl = new AbortController();
        const abortIdle = () => ctrl.abort('idle-timeout');
        const abortTotal = () => ctrl.abort('total-timeout');
        let timer = setTimeout(abortIdle, SUB_IDLE_MS);
        const totalTimer = setTimeout(abortTotal, SUB_TOTAL_MS);
        const kick = () => {
            clearTimeout(timer);
            timer = setTimeout(abortIdle, SUB_IDLE_MS);
        };
        try {
            const res = await fetch(url, { signal: ctrl.signal, redirect: 'follow' });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const total = parseInt(res.headers.get('content-length') || '0', 10);

            // No streaming support — fall back to buffering the whole body.
            // Without progress events a slow-but-active transfer cannot be told
            // apart from a stalled one, so keep resetting the idle timer and
            // rely on the total-timeout backstop to end true stalls (worst case
            // for a stall here is the 5-minute total timeout, not the idle one).
            if (!res.body || typeof res.body.getReader !== 'function') {
                const keepAlive = setInterval(kick, Math.min(10000, SUB_IDLE_MS));
                try {
                    const text = await res.text();
                    onProgress(new TextEncoder().encode(text).length, total);
                    return text;
                } finally {
                    clearInterval(keepAlive);
                }
            }

            const reader = res.body.getReader();
            const parts = [];
            let loaded = 0;
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                kick();
                parts.push(value);
                loaded += value.length;
                onProgress(loaded, total);
            }

            const buf = new Uint8Array(loaded);
            let offset = 0;
            for (const part of parts) {
                buf.set(part, offset);
                offset += part.length;
            }
            return new TextDecoder('utf-8').decode(buf);
        } catch (e) {
            // Both timers abort the same controller, so tell the two timeouts
            // apart by the abort reason and report the right one. Older
            // browsers ignore the reason argument and keep the old message.
            if (e && e.name === 'AbortError' && ctrl.signal.reason === 'total-timeout') {
                const total = new Error('Total timeout');
                total.name = 'SubTotalTimeout';
                throw total;
            }
            throw e;
        } finally {
            clearTimeout(timer);
            clearTimeout(totalTimer);
        }
    }

    // Direct-only fetching: the subscription URL (token included) is sent to the
    // provider itself and never to a third-party proxy. Providers without CORS
    // headers cannot be fetched from a browser — the error message below points
    // at the paste-contents fallback instead.
    async function fetchSubBody(url, onProgress) {
        return await fetchTextWithProgress(url, onProgress);
    }

    function setSubError(text) {
        subParsed.textContent = '';
        const err = document.createElement('div');
        err.className = 'error-msg';
        err.textContent = '⚠️ ' + text;
        subParsed.appendChild(err);
    }

    // Opens a subscription link for manual copying. The URL always comes from
    // the user's own paste (validated as a link before any call site runs),
    // so this is equivalent to them opening it from the address bar.
    function openSubLink(url) {
        window.open(url, '_blank', 'noopener');
    }

    // Enables the Open-link button exactly when the field holds a link.
    function syncOpenButton() {
        btnOpenSub.disabled = subValidate(subUrl.value.trim()) !== 'link';
    }

    // Step-by-step fallback shown when the provider blocks browser fetches.
    // Built with DOM APIs only (no innerHTML): every string here is static,
    // the only variable part is the link passed to window.open on click.
    function setSubCorsGuide(linkUrl) {
        const guide = document.createElement('div');
        guide.className = 'sub-guide';
        const title = document.createElement('div');
        title.textContent = 'Get the content manually — 3 quick steps:';
        const steps = document.createElement('ol');
        const first = document.createElement('li');
        first.textContent = 'Open your subscription link in a new tab: ';
        const openBtn = document.createElement('button');
        openBtn.type = 'button';
        openBtn.className = 'btn-subtle';
        openBtn.textContent = '↗ Open link';
        openBtn.addEventListener('click', () => openSubLink(linkUrl));
        first.appendChild(openBtn);
        const second = document.createElement('li');
        second.textContent = 'Select everything there and copy it (Ctrl+A, then Ctrl+C).';
        const third = document.createElement('li');
        third.textContent = 'Paste it into the box above and press Fetch & Enhance.';
        steps.append(first, second, third);
        guide.append(title, steps);
        subParsed.appendChild(guide);
    }

    // Accept a saved subscription file (.txt) dropped onto the card. Everything
    // stays local: FileReader never uploads anything.
    const SUB_MAX_FILE_BYTES = 2 * 1024 * 1024;

    // A drop error must not leave a previous output on screen either.
    function onSubDropError(text) {
        setSubError(text);
        subOutputSection.style.display = 'none';
        subOutputUrl.textContent = '';
        subOutputRemark.textContent = '';
        subResults = [];
        subRawConfigs = [];
    }
    function onSubDragOver(e) {
        e.preventDefault();
        subCard.classList.add('dragover');
    }
    function onSubDragLeave(e) {
        e.preventDefault();
        // dragleave also fires when moving between children of the card —
        // only clear the highlight when the pointer truly leaves it.
        if (e.relatedTarget && subCard.contains(e.relatedTarget)) return;
        subCard.classList.remove('dragover');
    }
    function onSubDrop(e) {
        e.preventDefault();
        subCard.classList.remove('dragover');
        const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
        if (!file) return;
        if (file.size > SUB_MAX_FILE_BYTES) {
            onSubDropError('That file is too large — drop a plain-text subscription file (.txt), usually a few hundred KB at most.');
            return;
        }
        const reader = new FileReader();
        reader.onload = () => {
            subUrl.value = String(reader.result || '');
            onSubInput();
            subUrl.focus();
        };
        reader.onerror = () => onSubDropError('Could not read that file.');
        reader.readAsText(file);
    }

    // Transport failures surface as TypeError in every browser, but the message
    // text varies ('Failed to fetch', 'NetworkError', 'Load failed', or even
    // empty), so match the name first and the text only as fallback.
    function subIsBlockedError(e) {
        const msg = (e && e.message) || String(e);
        return (e && e.name === 'TypeError') || /Failed to fetch|NetworkError|Load failed/i.test(msg);
    }

    // Reports the fetch error honestly. A 4xx/5xx from the provider is a real
    // answer, and the CORS case gets a message that points at the paste fallback.
    function subErrorText(e) {
        const msg = (e && e.message) || String(e);
        if (typeof navigator !== 'undefined' && navigator.onLine === false) {
            return 'You appear to be offline — check your connection and try again.';
        }
        if (e && e.name === 'SubTotalTimeout') {
            return 'The download took longer than ' + Math.round(SUB_TOTAL_MS / 60000) +
                ' minutes without finishing — the provider is too slow. Retry, or paste the subscription contents into this box.';
        }
        if (e && e.name === 'AbortError') {
            return 'The connection went silent for ' + Math.round(SUB_IDLE_MS / 1000) +
                's — the provider is throttling or unreachable. Retry, or paste the subscription contents into this box.';
        }
        if (/^HTTP \d+$/.test(msg)) {
            const code = Number(msg.slice(5));
            return 'The server replied ' + code + '. ' +
                (code === 401 || code === 403
                    ? 'That looks like an expired or invalid subscription link.'
                    : code === 404
                        ? 'That subscription link does not exist.'
                        : 'The subscription URL is wrong or the server is refusing it.');
        }
        if (subIsBlockedError(e)) {
            return 'This provider blocks browser access (it sends no CORS headers), so the direct fetch ' +
                'was refused. Open the link in a new tab and paste its contents into this box — that always works.';
        }
        return 'Could not read the response (' + msg + ').';
    }

    // One http(s) line = a link to fetch. Anything else that looks like a
    // subscription body is enhanced straight away, with no fetch at all — the
    // escape hatch for providers that block browser/CORS access.
    function subIsLink(v) {
        return !/\s/.test(v) && /^https?:\/\/\S+$/i.test(v);
    }

    // Mirrors extractSubConfigs() instead of guessing from the first line or a
    // length threshold: any line with a known scheme counts, and a short base64
    // blob is accepted if it actually decodes to a config.
    function subLooksLikeContent(v) {
        if (extractLines(v).some(l => SUB_SCHEME.test(l))) return true;
        const whole = safeAtob(v.replace(/\s+/g, ''));
        return !!whole && extractLines(whole).some(l => SUB_SCHEME.test(l));
    }

    // A single http(s) URL with an explicit port but no path, query or hash is
    // far more likely an HTTP proxy address than a subscription link (those
    // carry a path, a query token, or both). Userinfo is allowed: proxies
    // commonly embed credentials while subscription links effectively never do.
    // Fetching a proxy port would only fail confusingly, so reject it up front
    // with guidance instead of treating it as a link to fetch.
    function subLooksLikeProxy(v) {
        if (/\s/.test(v) || !/^https?:\/\/\S+$/i.test(v)) return false;
        let u = null;
        try {
            u = new URL(v);
        } catch (e) {
            return false;
        }
        return !!u.hostname && !!u.port &&
            (u.pathname === '/' || u.pathname === '') && !u.search && !u.hash;
    }

    // Returns 'link', 'content', 'proxy' or null for input that is none of those.
    // Both the input handler and the post-fetch re-validation go through this,
    // so a field that was replaced with junk mid-fetch can never re-enable
    // the button.
    function subValidate(v) {
        if (subLooksLikeProxy(v)) return 'proxy';
        if (subIsLink(v)) {
            let u = null;
            try {
                u = new URL(v);
            } catch (e) {
                u = null;
            }
            return u && u.hostname ? 'link' : null;
        }
        return subLooksLikeContent(v) ? 'content' : null;
    }

    // Verdicts that allow the Fetch button to run.
    function subCanRun(mode) {
        return mode === 'link' || mode === 'content';
    }

    function subShowInfo(label, value) {
        subParsed.textContent = '';
        const row = document.createElement('div');
        row.className = 'info-row';
        const key = document.createElement('span');
        key.className = 'info-label';
        key.textContent = label;
        const val = document.createElement('span');
        val.className = 'info-value';
        val.textContent = value;
        row.append(key, val);
        subParsed.appendChild(row);
    }

    function onSubInput() {
        const raw = subUrl.value.trim();
        subCard.classList.remove('valid', 'invalid');
        subProtocolTag.classList.remove('active');
        subProtocolTag.textContent = '—';
        subRawConfigs = [];

        // Any edit invalidates the previous result: leaving a 65-line output and
        // its Copy/Download buttons under a new error message is misleading.
        subOutputSection.style.display = 'none';
        subOutputUrl.textContent = '';
        subOutputRemark.textContent = '';
        subResults = [];
        subParsed.textContent = '';
        subHint.style.color = '';
        btnOpenSub.disabled = true;

        if (!raw) {
            btnSub.disabled = true;
            subHint.textContent = 'Paste a subscription link — or its contents — to enable';
            return;
        }

        subMode = subValidate(raw);
        if (subMode === 'link') {
            const u = new URL(raw);
            subCard.classList.add('valid');
            subProtocolTag.textContent = u.protocol.replace(':', '').toUpperCase() || 'HTTP';
            subProtocolTag.classList.add('active');
            subShowInfo('Host', u.hostname);
            btnSub.disabled = false;
            btnOpenSub.disabled = false;
            subHint.textContent = 'Ready to fetch and enhance';
            subHint.style.color = '#4cdf86';
            return;
        }

        if (subMode === 'content') {
            subCard.classList.add('valid');
            subProtocolTag.textContent = 'CONTENT';
            subProtocolTag.classList.add('active');
            subShowInfo('Mode', 'Pasted content — nothing will be fetched');
            btnSub.disabled = false;
            subHint.textContent = 'Ready to enhance pasted content';
            subHint.style.color = '#4cdf86';
            return;
        }

        if (subMode === 'proxy') {
            subMode = null;
            setSubError('That looks like an HTTP proxy address, not a subscription link. Only VLESS and Trojan URLs can be enhanced — paste one of those, or a subscription link. If this is actually a subscription served at a bare address with no path, open it in a new tab and paste its contents here instead.');
            btnSub.disabled = true;
            subHint.textContent = 'Paste a subscription link or a VLESS/Trojan URL';
            return;
        }

        subMode = null;
        setSubError('Invalid input. Paste a link starting with http:// or https://, or paste the subscription contents.');
        btnSub.disabled = true;
        subHint.textContent = 'Paste a valid link above to enable';
    }

    // Single render path for both modes: enhance the parsed configs, show counts,
    // and hand the same text to the copy / .txt / base64 .txt actions.
    // focus=true is passed only by an explicit Fetch — an option tweak re-renders
    // in place and must not yank the page down to the output.
    function renderSubResults(configs, focus) {
        let enhanced = [];
        let skipped = 0;
        let invalid = 0;
        configs.forEach(line => {
            const p = parseProxyURLSingle(line);
            if (!p || p.error) {
                invalid++;
                return;
            }
            if (p.protocol !== 'vless' && p.protocol !== 'trojan') {
                skipped++;
                return;
            }
            const res = enhanceURL(line, { ignoreServer: true });
            if (res && res.url) {
                enhanced.push(res.url);
            } else {
                skipped++;
            }
        });

        if (enhanced.length === 0) {
            subOutputSection.style.display = 'none';
            subResults = [];
            subHint.textContent = configs.length
                ? 'Found configs, but none were VLESS/Trojan with a usable URL'
                : 'No proxy configs found in the input';
            subHint.style.color = '#f0c040';
            subCard.classList.remove('valid');
            subCard.classList.add('invalid');
            setSubError(configs.length
                ? configs.length + ' config(s) found, but none could be enhanced — only VLESS and Trojan URLs are supported.'
                : 'No recognizable VLESS/VMess/Trojan/SS/SOCKS configs in the input. Open the link in a new tab and paste its contents here.');
            return;
        }

        subResults = enhanced;

        // A previous fetch may have failed without an edit in between — its
        // error and its red card styling must not sit next to this output.
        subParsed.textContent = '';
        subCard.classList.remove('invalid');
        subCard.classList.add('valid');

        const parts = ['✨ ' + enhanced.length + ' enhanced config(s)'];
        if (skipped) parts.push('skipped ' + skipped + ' non-VLESS/Trojan');
        if (invalid) parts.push('ignored ' + invalid + ' unparseable line(s)');
        subOutputRemark.textContent = parts.join(' · ');
        subOutputUrl.textContent = enhanced.join('\n');
        subOutputSection.style.display = 'block';
        if (focus) subOutputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        subHint.textContent = 'Done';
        subHint.style.color = '#4cdf86';
    }

    // Options live in this tab (shared node with the Enhancer tab), so changing
    // fp / cs / fm re-enhances the configs fetched earlier instead of leaving a
    // stale output on screen.
    function scheduleSubRender() {
        if (subBusy || !subRawConfigs.length) return;
        clearTimeout(subRenderTimer);
        subRenderTimer = setTimeout(() => {
            subRenderTimer = null;
            if (subBusy || !subRawConfigs.length) return;
            renderSubResults(subRawConfigs);
        }, 300);
    }

    // Shared by the fetch success and error paths: the field changed mid-fetch,
    // so drop whatever came back and say so — never render anything, error or
    // output, under input it no longer belongs to.
    function onSubStale() {
        subRawConfigs = [];
        btnSub.disabled = !subCanRun(subValidate(subUrl.value.trim()));
        syncOpenButton();
        subHint.textContent = 'Input changed during the fetch — fetch again';
        subHint.style.color = '#f0c040';
    }

    function onSubFetched(body, fetchRaw) {
        if (!subBusy) return;
        subBusy = false;
        // A queued progress tick must not overwrite the final status.
        if (subProgressTimer) {
            clearTimeout(subProgressTimer);
            subProgressTimer = null;
        }
        if (subRenderTimer) {
            clearTimeout(subRenderTimer);
            subRenderTimer = null;
        }
        // The field may have been replaced mid-fetch. Never render a body under
        // input it no longer belongs to: the input handler already wiped the
        // previous output, so there is nothing to show until the next fetch.
        if (subUrl.value.trim() !== fetchRaw) {
            onSubStale();
            return;
        }
        btnSub.disabled = false;
        syncOpenButton();
        // Note: the Enhancer's server field and its lastAutoServer tracking are
        // deliberately untouched here — subscriptions call enhanceURL with
        // ignoreServer:true, so they never read the field, and clearing
        // lastAutoServer alone would desync the auto-fill logic on next paste.
        const configs = extractSubConfigs(body);
        subRawConfigs = configs;
        renderSubResults(configs, true);
    }

    function onSubProgress(loaded, total) {
        if (subProgressTimer) return;
        subProgressTimer = setTimeout(() => {
            subProgressTimer = null;
            if (!subBusy) return;
            const kb = Math.round(loaded / 1024);
            subHint.textContent = total
                ? 'Fetching… ' + kb + ' / ' + Math.round(total / 1024) + ' KB'
                : 'Fetching… ' + kb + ' KB';
        }, 150);
    }

    async function onSub() {
        const raw = subUrl.value.trim();
        if (!raw || subBusy) return;

        // Validate freshly rather than trusting the cached subMode: the field may
        // have changed since the last input event.
        subMode = subValidate(raw);
        if (!subCanRun(subMode)) {
            onSubInput();
            return;
        }

        // Pasted content: no fetch at all.
        if (subMode === 'content') {
            subRawConfigs = extractSubConfigs(raw);
            renderSubResults(subRawConfigs, true);
            return;
        }

        subBusy = true;
        btnSub.disabled = true;
        btnOpenSub.disabled = true;
        subHint.textContent = 'Fetching…';
        subHint.style.color = '';
        // A retry without an edit must not keep the previous error — or the
        // previous red card styling — on screen. The old output is hidden too,
        // so a failed retry cannot leave stale configs next to the new error.
        subParsed.textContent = '';
        subCard.classList.remove('invalid');
        subOutputSection.style.display = 'none';
        subResults = [];
        subRawConfigs = [];

        try {
            const body = await fetchSubBody(raw, onSubProgress);
            onSubFetched(body, raw);
        } catch (e) {
            subBusy = false;
            if (subProgressTimer) {
                clearTimeout(subProgressTimer);
                subProgressTimer = null;
            }
            if (subUrl.value.trim() !== raw) {
                onSubStale();
                return;
            }
            btnSub.disabled = false;
            syncOpenButton();
            subHint.textContent = 'Fetch failed';
            subHint.style.color = '#f05050';
            subCard.classList.remove('valid');
            subCard.classList.add('invalid');
            setSubError(subErrorText(e));
            if (subIsBlockedError(e) && (typeof navigator === 'undefined' || navigator.onLine !== false)) setSubCorsGuide(raw);
        }
    }

    function downloadText(name, text, mime) {
        const blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function onCopySub(btn, text) {
        if (!text) return;
        // file:// / plain http have no async clipboard — fail with guidance
        // instead of an uncaught TypeError (sync throw, .catch can't see it).
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
            subHint.textContent = 'Copy failed — select the output text and copy it manually';
            subHint.style.color = '#f0c040';
            return;
        }
        navigator.clipboard.writeText(text).then(() => {
            btn.classList.add('copied');
            btn.innerHTML = '<span class="copy-icon">✅</span> Copied!';
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.innerHTML = '<span class="copy-icon">📋</span> Copy';
            }, 2000);
        }).catch(() => {
            subHint.textContent = 'Copy failed — select the output text and copy it manually';
            subHint.style.color = '#f0c040';
        });
    }

    subUrl.addEventListener('input', onSubInput);
    subClear.addEventListener('click', () => {
        subUrl.value = '';
        onSubInput();
    });
    btnSub.addEventListener('click', onSub);
    btnOpenSub.addEventListener('click', () => {
        const v = subUrl.value.trim();
        if (subValidate(v) === 'link') openSubLink(v);
    });
    subCard.addEventListener('dragenter', onSubDragOver);
    subCard.addEventListener('dragover', onSubDragOver);
    subCard.addEventListener('dragleave', onSubDragLeave);
    subCard.addEventListener('drop', onSubDrop);
    // Re-run the enhancement when the shared options change (selects vs textareas).
    [enhancerFp, enhancerFmPreset].forEach(el => el.addEventListener('change', scheduleSubRender));
    [enhancerCs, enhancerFm].forEach(el => el.addEventListener('input', scheduleSubRender));
    btnCopySub.addEventListener('click', () => onCopySub(btnCopySub, subResults.join('\n')));
    btnDownloadSub.addEventListener('click', () => {
        if (!subResults.length) return;
        downloadText('enhanced-configs.txt', subResults.join('\n') + '\n');
    });
    btnDownloadSubB64.addEventListener('click', () => {
        if (!subResults.length) return;
        // Standard subscription body: UTF-8 bytes -> base64, no line breaks.
        // Chunked because a spread over a few hundred KB overflows the arg limit.
        const bytes = new TextEncoder().encode(subResults.join('\n'));
        let bin = '';
        for (let i = 0; i < bytes.length; i += 0x8000) {
            bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
        }
        downloadText('enhanced-configs-base64.txt', btoa(bin));
    });

    // ===== Main Tab switching =====
    // The Enhancement Options card is one shared node: it is moved into whichever
    // of the two enhancer-driven tabs is active, so both always read the same
    // fp / cs / fm values instead of drifting apart as two copies would.
    const enhancerOptionsCard = document.getElementById('enhancer-options-card');
    const enhancerOptionsSlot = document.getElementById('enhancer-options-slot');
    const subOptionsSlot = document.getElementById('sub-options-slot');

    function switchMainTab(viewName) {
        mainTabs.forEach(t => {
            t.classList.toggle('active', t.dataset.view === viewName);
        });
        viewChain.style.display = viewName === 'chain' ? '' : 'none';
        viewEnhancer.style.display = viewName === 'enhancer' ? '' : 'none';
        viewSub.style.display = viewName === 'sub' ? '' : 'none';
        viewEch.style.display = viewName === 'ech' ? '' : 'none';

        const optionsTarget = viewName === 'sub' ? subOptionsSlot : enhancerOptionsSlot;
        if (enhancerOptionsCard && optionsTarget) optionsTarget.appendChild(enhancerOptionsCard);
        document.querySelectorAll('.protocol-badges .badge').forEach(badge => {
            const show = viewName === 'chain' || ['vless', 'trojan'].includes(badge.dataset.protocol);
            badge.style.display = show ? '' : 'none';
        });
    }

    mainTabs.forEach(tab => {
        tab.addEventListener('click', () => switchMainTab(tab.dataset.view));
    });

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

    // Apply badge visibility for the initial view (ech is active by default)
    switchMainTab('ech');


    function switchSubTab(subTabName) {
        // Scoped to the sing-box output: the ECH view has its own sub-tabs
        // with a dedicated switcher below.
        const subTabs = document.querySelectorAll('#panel-singbox .sub-tab');
        const subPanels = document.querySelectorAll('#panel-singbox .sub-panel');

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

    // Sub-tab switching (sing-box output only — the ECH view has its own
    // switcher; binding these globally would strip sing-box panels when an
    // ECH sub-tab, which carries data-echsubtab instead, is clicked).
    document.querySelectorAll('#panel-singbox .sub-tab').forEach(btn => {
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
    // ECH presets (own tab) — selecting one overwrites the textarea, so
    // anything typed by hand afterwards is preserved. 'none' only clears it.
    // The textarea ships prefilled with the default (cf-udp) preset value.
    const ECH_PRESETS = {
        'cf-alidns': 'cloudflare-ech.com+https://dns.alidns.com/dns-query',
        'cf-udp': 'cloudflare-ech.com+udp://1.1.1.1',
        'esni-alidns': 'encryptedsni.com+https://dns.alidns.com/dns-query',
        'esni-udp': 'encryptedsni.com+udp://1.1.1.1',
        'sspcc-udp': 'ech.sspcccdn.xyz+udp://1.1.1.1',
        'ipgs-udp': 'ip.gs+udp://8.8.8.8'
    };
    if (echPreset) {
        echPreset.addEventListener('change', () => {
            echText.value = ECH_PRESETS[echPreset.value] || '';
        });
    }
    echInput.addEventListener('input', onEchInput);
    echInput.addEventListener('paste', () => setTimeout(onEchInput, 50));
    echClear.addEventListener('click', () => {
        echInput.value = '';
        onEchInput();
    });
    btnEchEnhance.addEventListener('click', onEchEnhance);
    btnCopyEch.addEventListener('click', () => {
        const text = echOutputUrl.textContent;
        if (!text) return;
        // file:// / plain http have no async clipboard — fail with guidance
        // instead of an uncaught TypeError (sync throw, .catch can't see it).
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
            echHint.textContent = 'Copy failed — select the output text and copy it manually';
            echHint.style.color = '#f0c040';
            return;
        }
        navigator.clipboard.writeText(text).then(() => {
            btnCopyEch.classList.add('copied');
            btnCopyEch.innerHTML = '<span class="copy-icon">✅</span> Copied!';
            setTimeout(() => {
                btnCopyEch.classList.remove('copied');
                btnCopyEch.innerHTML = '<span class="copy-icon">📋</span> Copy';
            }, 2000);
        }).catch(() => {
            echHint.textContent = 'Copy failed — select the output text and copy it manually';
            echHint.style.color = '#f0c040';
        });
    });
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
        // file:// / plain http have no async clipboard — fail with guidance
        // instead of an uncaught TypeError (sync throw, .catch can't see it).
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
            enhanceHint.textContent = 'Copy failed — select the output text and copy it manually';
            enhanceHint.style.color = '#f0c040';
            return;
        }
        navigator.clipboard.writeText(text).then(() => {
            btnCopyEnhancer.classList.add('copied');
            btnCopyEnhancer.innerHTML = '<span class="copy-icon">✅</span> Copied!';
            setTimeout(() => {
                btnCopyEnhancer.classList.remove('copied');
                btnCopyEnhancer.innerHTML = '<span class="copy-icon">📋</span> Copy';
            }, 2000);
        }).catch(() => {
            enhanceHint.textContent = 'Copy failed — select the output text and copy it manually';
            enhanceHint.style.color = '#f0c040';
        });
    });
    echSubInput.addEventListener('input', onEchSubInput);
    echSubInput.addEventListener('paste', () => setTimeout(onEchSubInput, 50));
    echSubClear.addEventListener('click', () => {
        echSubInput.value = '';
        onEchSubInput();
    });
    btnEchSub.addEventListener('click', onEchSub);
    btnEchOpenSub.addEventListener('click', () => {
        const raw = echSubInput.value.trim();
        if (subValidate(raw) === 'link') openSubLink(raw);
    });
    // ECH input-mode sub-tabs (scoped to #view-ech so the sing-box panels
    // driven by the generic switchSubTab are untouched).
    const echSubTabs = Array.from(document.querySelectorAll('#view-ech .sub-tab'));
    const echSubPanels = {
        url: document.getElementById('ech-subpanel-url'),
        sub: document.getElementById('ech-subpanel-sub')
    };
    function switchEchSubTab(name) {
        echSubTabs.forEach(t => t.classList.toggle('active', t.dataset.echsubtab === name));
        Object.entries(echSubPanels).forEach(([key, panel]) => {
            if (panel) panel.classList.toggle('active', key === name);
        });
    }
    echSubTabs.forEach(tab => {
        tab.addEventListener('click', () => switchEchSubTab(tab.dataset.echsubtab));
    });
    // Downloads export exactly what is displayed, so Copy and both files
    // always agree (URL mode shows blank-line separation, sub mode single).
    btnDownloadEch.addEventListener('click', () => {
        if (!echOutputList.length) return;
        downloadText('ech-enhanced-configs.txt', echOutputUrl.textContent + '\n');
    });
    btnDownloadEchB64.addEventListener('click', () => {
        if (!echOutputList.length) return;
        // Standard subscription body: UTF-8 bytes -> base64, no line breaks.
        // Chunked because a spread over a few hundred KB overflows the arg limit.
        const bytes = new TextEncoder().encode(echOutputUrl.textContent);
        let bin = '';
        for (let i = 0; i < bytes.length; i += 0x8000) {
            bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
        }
        downloadText('ech-enhanced-configs-base64.txt', btoa(bin));
    });
    echSubCard.addEventListener('dragenter', onEchSubDragOver);
    echSubCard.addEventListener('dragover', onEchSubDragOver);
    echSubCard.addEventListener('dragleave', onEchSubDragLeave);
    echSubCard.addEventListener('drop', onEchSubDrop);
    // Re-run stored subscription configs when the ECH options change.
    // (Server is ignored for bulk input, so it is not watched.)
    [echFp, echPreset].forEach(el => el.addEventListener('change', scheduleEchSubRender));
    [echText].forEach(el => el.addEventListener('input', scheduleEchSubRender));
})();
