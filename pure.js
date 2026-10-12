// ===================================================================
// Proxy Builder — pure.js
// Pure helpers with no DOM or network access (testable in Node).
// Loaded before script.js; both share classic <script> global scope.
// Future pure helpers MUST go here with tests in tests/pure.test.js.
// ===================================================================

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

// Standard subscription body: UTF-8 bytes -> base64, no line breaks.
// Chunked because a spread over a few hundred KB overflows the arg limit.
function encodeUtf8ToB64(text) {
    const bytes = new TextEncoder().encode(String(text ?? ''));
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
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

// ===== ECH Helpers =====
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

// ===== Enhance Cores =====
// DOM-free cores behind value-in/value-out signatures: script.js wrappers
// read the option elements and delegate; bulk paths pass ignoreServer.
// NOTE the two functions DIFFER on fp==='none'/empty by design — fragment
// keeps the existing fp, ECH deletes it. Preserve the asymmetry, do not unify.
function enhanceUrlCore(raw, opts) {
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
    const server = (opts && opts.ignoreServer) ? '' : ((opts && opts.server) || '').trim();
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
    const fp = ((opts && opts.fp) || '').trim();
    if (fp && fp !== 'none') {
        params.set('fp', fp);
    }

    // Cipher suites & fragment mask — only meaningful with TLS
    if (security === 'tls') {
        const cs = ((opts && opts.cs) || '').trim();
        if (cs) {
            params.set('cs', cs);
        }
        const fm = ((opts && opts.fm) || '').trim();
        if (fm) {
            params.set('fm', fm);
        }
    }

    // URLSearchParams encodes spaces as '+', but v2ray-style clients use '%20'
    u.search = u.search.replace(/\+/g, '%20');

    return { url: u.toString() };
}

function enhanceEchUrlCore(raw, opts) {
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
    const server = (opts && opts.ignoreServer) ? '' : ((opts && opts.server) || '').trim();
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
    const fp = ((opts && opts.fp) || '').trim();
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
        const ech = normalizeEchInput((opts && opts.ech) || '');
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

// ===== URL Parser =====
function extractLines(raw) {
    if (!raw) return [];
    return raw
        .split(/[\r\n]+/)
        .map(line => line.trim())
        .filter(line => line.length > 0);
}

// ===== Subscription Helpers =====
// One scheme list for every branch of the bulk path, so a scheme added here
// works in plain text, whole-blob base64 and per-line base64 alike.
const SUB_SCHEME = /^(vless|vmess|trojan|ss|socks5?|tg):\/\//i;

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

// ===== Subscription Extract & Errors =====
// Moved from script.js: DOM-free bulk decode plus error classifiers, shared
// via classic <script> global scope. The timeout/message consts live here (not
// in script.js) so subErrorText() resolves them in both runtimes: browsers
// through the shared global scope, Node tests by requiring this file.
const SUB_IDLE_MS = 30000;
// Backstop for a body that trickles forever without ever going silent.
const SUB_TOTAL_MS = 5 * 60 * 1000;
const SUB_TOO_LARGE_MSG = 'That file is too large — drop a plain-text subscription file (.txt), usually a few hundred KB at most.';

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

// Transport failures surface as TypeError in every browser, but the message
// text varies ('Failed to fetch', 'NetworkError', 'Load failed', or even
// empty), so match the name first and the text only as fallback.
function subIsBlockedError(e) {
    const msg = (e && e.message) || String(e);
    return (e && e.name === 'TypeError') || /Failed to fetch|NetworkError|Load failed/i.test(msg);
}

// Reports the fetch error honestly. A 4xx/5xx from the provider is a real
// answer, and the CORS case gets a message that points at the paste fallback.
function subErrorText(e, isOnline = (typeof navigator !== 'undefined' ? navigator.onLine !== false : true)) {
    const msg = (e && e.message) || String(e);
    if (isOnline === false) {
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
    if (e && e.name === 'SubTooLarge') {
        return SUB_TOO_LARGE_MSG;
    }
    return 'Could not read the response (' + msg + ').';
}


// ===== Proxy Parsers =====
// Moved from script.js: DOM-free URL parsers shared via classic <script> global scope.

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

function parseVless(url) {
    try {
        const u = new URL(url);
        if (!u.username) return { error: 'Failed to parse VLESS URL: missing userinfo' };
        const uuid = u.username;
        if (!uuid) return { error: 'Failed to parse VLESS URL: missing userinfo' };
        const params = Object.fromEntries(u.searchParams);
        return {
            protocol: 'vless',
            uuid: uuid,
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
            remark: String(config.ps ?? ''),
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
        if (!u.username) return { error: 'Failed to parse Trojan URL: missing userinfo' };
        const password = safeDecode(u.username);
        if (!password) return { error: 'Failed to parse Trojan URL: missing userinfo' };
        const params = Object.fromEntries(u.searchParams);
        return {
            protocol: 'trojan',
            password: password,
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
        // A stray path (socks://host/extra) is not part of the server name.
        hostPart = hostPart.split('/')[0];

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
        // A stray path (http://host/extra) is not part of the server name.
        hostPart = hostPart.split('/')[0];

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

// ===== Display Helpers =====
// Coerce first: callers may pass through unknown JSON types (e.g. a numeric
// VMess "ps"), and String() is idempotent for strings.
function maskString(str) {
    str = String(str ?? '');
    if (!str || str.length <= 8) return str;
    return str.slice(0, 4) + '••••' + str.slice(-4);
}

function truncateStr(str, max) {
    str = String(str ?? '');
    if (!str || str.length <= max) return str;
    return str.slice(0, max) + '…';
}

// ===== Presets =====
// Fragment presets — switching only overwrites the textarea on explicit
// selector change, so manual edits are always preserved.
const FRAGMENT_PRESETS = {
    v1: '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}',
    v2: '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}'
};
// ECH presets (own tab) — selecting one overwrites the textarea, so
// anything typed by hand afterwards is preserved. 'none' only clears it.
// The textarea ships prefilled with the default (ech-1) preset value.
const ECH_PRESETS = {
    'ech-1': 'cloudflare-ech.com+udp://1.1.1.1',
    'ech-2': 'cloudflare-ech.com+udp://9.9.9.9',
    'ech-3': 'cloudflare-ech.com+udp://208.67.222.222',
    'ech-4': 'cloudflare-ech.com+udp://8.8.8.8',
    'ech-5': 'cloudflare-ech.com+udp://1.0.0.1',
    'ech-6': 'cloudflare-ech.com+udp://8.8.4.4',
    'ech-7': 'cloudflare-ech.com+udp://149.112.112.112',
    'ech-8': 'cloudflare-ech.com+udp://208.67.220.220',
    'ech-9': 'cloudflare-ech.com+udp://76.76.19.19',
    'ech-10': 'cloudflare-ech.com+udp://76.76.2.0',
    'ech-11': 'cloudflare-ech.com+udp://94.140.14.14',
    'ech-12': 'cloudflare-ech.com+udp://94.140.15.15',
    'ech-13': 'cloudflare-ech.com+udp://64.6.64.6',
    'ech-14': 'cloudflare-ech.com+udp://64.6.65.6',
    'ech-15': 'cloudflare-ech.com+udp://45.90.28.0',
    'ech-16': 'cloudflare-ech.com+udp://45.90.30.0',
    'ech-17': 'cloudflare-ech.com+udp://185.228.168.9',
    'ech-18': 'cloudflare-ech.com+udp://185.228.169.9'
};

// Node test harness: browsers ignore this block (`module` is undefined there).
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        safeAtob, encodeUtf8ToB64, safeDecode, extractLines,
        getEchQueryServer, ECH_DNS_DEFAULT, isBareEchDomain, normalizeEchInput,
        ECH_PRESETS, FRAGMENT_PRESETS, SUB_SCHEME,
        enhanceUrlCore, enhanceEchUrlCore,
        parseProxyURLSingle, parseProxyURL, parseVless, parseVmess, parseTrojan, parseShadowsocks, parseSocks, parseHttp,
        maskString, truncateStr,
        subIsLink, subLooksLikeContent, subLooksLikeProxy, subValidate,
        SUB_IDLE_MS, SUB_TOTAL_MS, SUB_TOO_LARGE_MSG,
        extractSubConfigs, subIsBlockedError, subErrorText
    };
}
