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
        safeAtob, safeDecode, extractLines,
        getEchQueryServer, ECH_DNS_DEFAULT, isBareEchDomain, normalizeEchInput,
        ECH_PRESETS, FRAGMENT_PRESETS, SUB_SCHEME,
        subIsLink, subLooksLikeContent, subLooksLikeProxy, subValidate
    };
}
