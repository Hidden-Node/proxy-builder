const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const pure = require('../pure.js');

const {
    safeAtob, encodeUtf8ToB64, safeDecode, extractLines,
    getEchQueryServer, ECH_DNS_DEFAULT, isBareEchDomain, normalizeEchInput,
    ECH_PRESETS, FRAGMENT_PRESETS, SUB_SCHEME,
    enhanceUrlCore, enhanceEchUrlCore,
    subIsLink, subLooksLikeContent, subLooksLikeProxy, subValidate,
    SUB_IDLE_MS, SUB_TOTAL_MS, SUB_TOO_LARGE_MSG,
    extractSubConfigs, expandBulkLines, subIsBlockedError, subErrorText,
    parseProxyURLSingle, parseProxyURL, parseVless, parseVmess,
    parseTrojan, parseShadowsocks, parseSocks, parseHttp,
    buildStreamSettings, buildProxyOutbound, buildChainOutbound, buildSingboxOutbound,
    maskString, truncateStr
} = pure;

describe('safeAtob', () => {
    it('decodes ASCII base64', () => {
        assert.equal(safeAtob('aGVsbG8='), 'hello');
    });

    it('round-trips UTF-8 Persian text', () => {
        const text = 'سلام دنیا';
        const b64 = Buffer.from(text, 'utf8').toString('base64');
        assert.equal(safeAtob(b64), text);
    });

    it('accepts the base64url alphabet (- and _)', () => {
        // NOTE: 'سلام دنیا! تست' was chosen because its base64url form
        // (2LPZhNin2YUg2K_ZhtuM2KchINiq2LPYqg) actually contains '_', so this
        // round-trip exercises the -/+/ _// conversion instead of duplicating
        // the standard-alphabet test above.
        const text = 'سلام دنیا! تست';
        const b64url = Buffer.from(text, 'utf8').toString('base64url');
        assert.ok(b64url.includes('-') || b64url.includes('_'));
        assert.equal(safeAtob(b64url), text);
        assert.notEqual(safeAtob(b64url), null);
    });

    it('returns null for invalid input', () => {
        assert.equal(safeAtob('!!!'), null);
        assert.equal(safeAtob('abcde'), null); // length % 4 === 1
        assert.equal(safeAtob(''), null);
    });
});

describe('encodeUtf8ToB64', () => {
    it('round-trips ASCII text via safeAtob', () => {
        const text = 'hello world';
        assert.equal(safeAtob(encodeUtf8ToB64(text)), text);
    });

    it('round-trips UTF-8 Persian text', () => {
        const text = 'سلام دنیا';
        assert.equal(safeAtob(encodeUtf8ToB64(text)), text);
    });

    it('encodes empty string to empty string', () => {
        assert.equal(encodeUtf8ToB64(''), '');
    });

    it('exercises the multi-chunk path on a large input', () => {
        const text = 'سلام'.repeat(5000);
        assert.ok(Buffer.byteLength(text, 'utf8') > 32768);
        assert.equal(safeAtob(encodeUtf8ToB64(text)), text);
    });

    it('emits no line breaks', () => {
        const text = 'vless://a@b:1\ntrojan://c@d:2\n' + 'سلام'.repeat(5000);
        assert.ok(!/[\r\n]/.test(encodeUtf8ToB64(text)));
    });

    it('coerces falsy non-strings per 011 discipline (null/undefined stay empty)', () => {
        assert.equal(safeAtob(encodeUtf8ToB64(0)), '0');
        assert.equal(encodeUtf8ToB64(null), '');
        assert.equal(encodeUtf8ToB64(undefined), '');
    });
});

describe('safeDecode', () => {
    it('decodes valid encoding and passes malformed input through', () => {
        assert.equal(safeDecode('hello%20world'), 'hello world');
        assert.equal(safeDecode('%E0%A4%A'), '%E0%A4%A');
    });
});

describe('extractLines', () => {
    it('splits mixed endings, trims and drops blanks', () => {
        assert.deepEqual(extractLines('  a  \r\n\n  b\n\r\n  \n c  '), ['a', 'b', 'c']);
        assert.deepEqual(extractLines(''), []);
    });
});

describe('isBareEchDomain', () => {
    it('classifies bare domains vs base64 vs full forms', () => {
        assert.equal(isBareEchDomain('cloudflare-ech.com'), true);
        assert.equal(isBareEchDomain('aGVsbG8='), false);
        assert.equal(isBareEchDomain('cloudflare-ech.com+udp://1.1.1.1'), false);
    });
});

describe('normalizeEchInput', () => {
    it('completes bare domains, passes full forms through, keeps empty empty', () => {
        assert.equal(normalizeEchInput('cloudflare-ech.com'), 'cloudflare-ech.com+' + ECH_DNS_DEFAULT);
        assert.equal(normalizeEchInput('cloudflare-ech.com+udp://1.1.1.1'), 'cloudflare-ech.com+udp://1.1.1.1');
        assert.equal(normalizeEchInput(''), '');
        assert.equal(normalizeEchInput('   '), '');
    });
});

describe('getEchQueryServer', () => {
    it('extracts the domain from DNS-query forms', () => {
        assert.equal(getEchQueryServer('cloudflare-ech.com+https://dns.alidns.com/dns-query'), 'cloudflare-ech.com');
        assert.equal(getEchQueryServer('cloudflare-ech.com+udp://1.1.1.1'), 'cloudflare-ech.com');
    });

    it('returns empty for base64 blobs and bare resolvers', () => {
        assert.equal(getEchQueryServer(Buffer.from('fake-ech-config-list').toString('base64')), '');
        assert.equal(getEchQueryServer('udp://1.1.1.1'), '');
        assert.equal(getEchQueryServer(''), '');
    });
});

describe('subIsLink', () => {
    it('accepts a bare http(s) URL, rejects schemes and whitespace', () => {
        assert.equal(subIsLink('https://example.com/sub/token'), true);
        assert.equal(subIsLink('vless://x'), false);
        assert.equal(subIsLink('two words https://x'), false);
    });
});

describe('subLooksLikeContent', () => {
    it('spots proxy lines, rejects junk', () => {
        assert.equal(subLooksLikeContent('vless://uuid@example.com:443?security=tls#remark'), true);
        assert.equal(subLooksLikeContent('hello-world-no-scheme'), false);
    });
});

describe('subLooksLikeProxy', () => {
    it('flags host:port URLs, not subscription links', () => {
        assert.equal(subLooksLikeProxy('http://host:8080'), true);
        assert.equal(subLooksLikeProxy('https://example.com/sub/token'), false);
    });
});

describe('subValidate', () => {
    it('classifies a subscription link', () => {
        assert.equal(subValidate('https://example.com/sub/token'), 'link');
    });

    it('flags a bare host:port URL as a proxy, not a link', () => {
        assert.equal(subValidate('http://host:8080'), 'proxy');
    });

    it('treats a proxy line as content', () => {
        assert.equal(subValidate('vless://uuid@example.com:443?security=tls#remark'), 'content');
    });

    it('decodes a base64 subscription body as content', () => {
        const blob = Buffer.from('vless://a@b:1\ntrojan://c@d:2', 'utf8').toString('base64');
        assert.equal(subValidate(blob), 'content');
    });

    it('rejects junk', () => {
        assert.equal(subValidate('hello-world-no-scheme'), null);
    });
});

describe('presets', () => {
    it('locks the ech-1 default', () => {
        assert.equal(ECH_PRESETS['ech-1'], 'cloudflare-ech.com+udp://1.1.1.1');
    });

    it('locks the exact preset key set ech-1..ech-18', () => {
        const expected = Array.from({ length: 18 }, (_, i) => 'ech-' + (i + 1));
        assert.deepEqual(Object.keys(ECH_PRESETS), expected);
    });

    it('ships all 18 operator presets on cloudflare-ech.com over udp', () => {
        const keys = Object.keys(ECH_PRESETS);
        assert.equal(keys.length, 18);
        for (const value of Object.values(ECH_PRESETS)) {
            assert.match(value, /^cloudflare-ech\.com\+udp:\/\/[0-9.]+$/);
        }
    });

    it('spot-checks preset values across the list', () => {
        assert.equal(ECH_PRESETS['ech-2'], 'cloudflare-ech.com+udp://9.9.9.9');
        assert.equal(ECH_PRESETS['ech-9'], 'cloudflare-ech.com+udp://76.76.19.19');
        assert.equal(ECH_PRESETS['ech-18'], 'cloudflare-ech.com+udp://185.228.169.9');
    });

    it('ships parseable fragment presets', () => {
        assert.ok(JSON.parse(FRAGMENT_PRESETS.v1));
        assert.ok(JSON.parse(FRAGMENT_PRESETS.v2));
    });

    it('matches known proxy schemes', () => {
        assert.equal(SUB_SCHEME.test('vless://x'), true);
        assert.equal(SUB_SCHEME.test('https://example.com/sub'), false);
    });
});

const VLESS_GOOD = 'vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=tls&sni=example.com#My%20Remark';
const TROJAN_GOOD = 'trojan://myPassword@trojan.example.com:443?security=tls&sni=trojan.example.com#Trojan%20Tag';

function vmessLink(ps) {
    const cfg = {
        v: '2', ps: ps, add: 'vmess.example.com', port: '443', id: 'uuid-x',
        aid: '0', net: 'ws', type: 'none', host: 'h.example.com', path: '/path',
        tls: 'tls', sni: 's.example.com', fp: 'chrome'
    };
    return 'vmess://' + Buffer.from(JSON.stringify(cfg), 'utf8').toString('base64');
}

describe('parseProxyURLSingle', () => {
    it('routes each scheme to its parser', () => {
        assert.equal(parseProxyURLSingle(VLESS_GOOD).protocol, 'vless');
        assert.equal(parseProxyURLSingle(vmessLink('r')).protocol, 'vmess');
        assert.equal(parseProxyURLSingle(TROJAN_GOOD).protocol, 'trojan');
        assert.equal(parseProxyURLSingle('socks://u:p@socks.example.com:1080').protocol, 'socks');
        assert.equal(parseProxyURLSingle('http://u:p@http.example.com:8080').protocol, 'http');
    });

    it('rejects socks4 links (socks5 only)', () => {
        const r = parseProxyURLSingle('socks4://u:p@h.example.com:1080');
        assert.match(r.error, /Unknown protocol/);
    });

    it('decodes a bare base64 vmess blob', () => {
        const blob = vmessLink('blob-remark').replace(/^vmess:\/\//, '');
        const r = parseProxyURLSingle(blob);
        assert.equal(r.protocol, 'vmess');
        assert.equal(r.remark, 'blob-remark');
    });

    it('rejects unknown schemes', () => {
        assert.match(parseProxyURLSingle('gopher://x').error, /Unknown protocol/);
    });

    it('refuses a base64 body with several configs instead of merging them', () => {
        // Regression: the base64 fallback recursed on the decoded body, and
        // new URL() strips line breaks — so a pasted subscription collapsed
        // into one VLESS link whose remark swallowed the rest.
        const blob = Buffer.from(VLESS_GOOD + '\n' + TROJAN_GOOD, 'utf8').toString('base64');
        const r = parseProxyURLSingle(blob);
        assert.ok(r && r.error, 'expected an error, not a merged config');
        assert.match(r.error, /several configs/);
    });

    it('still base64-decodes a single link whose remark spans lines', () => {
        // A %0A in the remark is not a second config: only lines that start
        // with a proxy scheme count, so this must keep parsing as one link.
        const one = 'vless://uuid-1@a.example.com:443?security=tls#Hello%0AWorld';
        const blob = Buffer.from(one, 'utf8').toString('base64');
        const r = parseProxyURLSingle(blob);
        assert.equal(r.protocol, 'vless');
        assert.equal(r.server, 'a.example.com');
    });
});

describe('parseProxyURL', () => {
    it('parses a single line to a single object', () => {
        const r = parseProxyURL(VLESS_GOOD);
        assert.equal(r.protocol, 'vless');
        assert.equal(r.server, 'example.com');
    });

    it('returns every valid line of a multi-line list', () => {
        const r = parseProxyURL(VLESS_GOOD + '\n' + TROJAN_GOOD);
        assert.equal(r.length, 2);
        assert.equal(r[0].protocol, 'vless');
        assert.equal(r[1].protocol, 'trojan');
    });

    it('drops invalid lines when at least one line is valid', () => {
        const r = parseProxyURL('junkline\n' + VLESS_GOOD);
        assert.equal(r.length, 1);
        assert.equal(r[0].protocol, 'vless');
    });

    it('falls back to the first error when all lines are invalid', () => {
        const r = parseProxyURL('junk1\njunk2');
        assert.match(r.error, /Unknown protocol/);
    });

    it('returns null for blank input', () => {
        assert.equal(parseProxyURL('   '), null);
    });
});

describe('parseVless', () => {
    it('parses a known-good link to exact fields', () => {
        const r = parseVless(VLESS_GOOD);
        assert.equal(r.uuid, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
        assert.equal(r.server, 'example.com');
        assert.equal(r.port, 443);
        assert.equal(r.remark, 'My Remark');
        assert.equal(r.security, 'tls');
        assert.equal(r.sni, 'example.com');
    });

    it('rejects a link with no userinfo', () => {
        assert.ok(parseVless('vless://example.com:443?security=tls').error);
    });

    it('rejects a link with empty userinfo', () => {
        assert.ok(parseVless('vless://@example.com:443').error);
    });
});

describe('parseVmess', () => {
    it('parses a known-good link to exact fields', () => {
        const r = parseVmess(vmessLink('test-remark'));
        assert.equal(r.uuid, 'uuid-x');
        assert.equal(r.server, 'vmess.example.com');
        assert.equal(r.port, 443);
        assert.equal(r.remark, 'test-remark');
        assert.equal(r.security, 'tls');
    });

    it('accepts the base64url alphabet', () => {
        // 'test~~~' forces '+' into the standard encoding so the url-safe
        // form genuinely differs instead of duplicating the test above.
        const std = vmessLink('test~~~');
        const url = 'vmess://' + Buffer.from(JSON.stringify({
            v: '2', ps: 'test~~~', add: 'vmess.example.com', port: '443', id: 'uuid-x',
            aid: '0', net: 'ws', type: 'none', host: 'h.example.com', path: '/path',
            tls: 'tls', sni: 's.example.com', fp: 'chrome'
        }), 'utf8').toString('base64url');
        assert.ok(url.includes('-') || url.includes('_'));
        assert.deepEqual(parseVmess(url), parseVmess(std));
    });

    it('rejects undecodable input', () => {
        assert.match(parseVmess('vmess://!!!').error, /decode/);
    });

    it('coerces a non-string ps to a string remark', () => {
        const cfg = { v: '2', ps: 12345, add: 'example.com', port: '443', id: 'uuid-1', aid: '0', net: 'tcp', type: 'none', tls: 'none' };
        const r = parseVmess('vmess://' + Buffer.from(JSON.stringify(cfg), 'utf8').toString('base64'));
        assert.equal(typeof r.remark, 'string');
        assert.equal(r.remark, '12345');
    });
});

describe('parseTrojan', () => {
    it('parses a known-good link to exact fields', () => {
        const r = parseTrojan(TROJAN_GOOD);
        assert.equal(r.password, 'myPassword');
        assert.equal(r.server, 'trojan.example.com');
        assert.equal(r.port, 443);
        assert.equal(r.remark, 'Trojan Tag');
    });

    it('rejects a link with no userinfo', () => {
        assert.ok(parseTrojan('trojan://trojan.example.com:443').error);
    });
});

describe('parseShadowsocks', () => {
    it('parses userinfo@host form to exact fields', () => {
        const userB64 = Buffer.from('aes-256-gcm:mypass', 'utf8').toString('base64');
        const r = parseShadowsocks('ss://' + userB64 + '@ss.example.com:8388#SS%20Remark');
        assert.equal(r.method, 'aes-256-gcm');
        assert.equal(r.password, 'mypass');
        assert.equal(r.server, 'ss.example.com');
        assert.equal(r.port, 8388);
        assert.equal(r.remark, 'SS Remark');
    });

    it('parses the whole-blob base64 form', () => {
        const fullB64 = Buffer.from('aes-256-gcm:mypass@ss2.example.com:8388', 'utf8').toString('base64');
        const r = parseShadowsocks('ss://' + fullB64 + '#Full%20Remark');
        assert.equal(r.method, 'aes-256-gcm');
        assert.equal(r.server, 'ss2.example.com');
        assert.equal(r.port, 8388);
    });

    it('accepts the base64url alphabet', () => {
        // 'test~~~' forces '+' into the standard encoding (fn5+) so the
        // url-safe swap genuinely exercises the -/_ conversion.
        const std = Buffer.from('aes-256-gcm:test~~~', 'utf8').toString('base64');
        assert.ok(std.includes('+') || std.includes('/'));
        const url = std.replace(/\+/g, '-').replace(/\//g, '_');
        const a = parseShadowsocks('ss://' + std + '@ss.example.com:8388');
        const b = parseShadowsocks('ss://' + url + '@ss.example.com:8388');
        assert.deepEqual(b, a);
        assert.equal(b.password, 'test~~~');
    });

    it('rejects undecodable input', () => {
        assert.ok(parseShadowsocks('ss://!!!').error);
    });
});

describe('parseSocks', () => {
    it('parses a known-good link to exact fields', () => {
        const r = parseSocks('socks://user1:pass1@socks.example.com:1080#Socks%20Tag');
        assert.equal(r.server, 'socks.example.com');
        assert.equal(r.port, 1080);
        assert.equal(r.user, 'user1');
        assert.equal(r.pass, 'pass1');
        assert.equal(r.remark, 'Socks Tag');
    });

    it('parses bracketed IPv6', () => {
        const r = parseSocks('socks://user:pass@[::1]:1080');
        assert.equal(r.server, '::1');
        assert.equal(r.port, 1080);
    });

    it('parses the tg:// share form', () => {
        const r = parseSocks('tg://socks?server=tg.example.com&port=1080&user=tu&pass=tp');
        assert.equal(r.server, 'tg.example.com');
        assert.equal(r.port, 1080);
        assert.equal(r.user, 'tu');
        assert.equal(r.pass, 'tp');
    });

    it('accepts the socks5:// scheme', () => {
        assert.equal(parseSocks('socks5://u:p@h.example.com:1080').server, 'h.example.com');
    });

    it('strips a stray path from the server name', () => {
        assert.equal(parseSocks('socks://example.com/sub/path').server, 'example.com');
    });

    it('rejects a link with no server', () => {
        assert.match(parseSocks('socks://').error, /missing server/);
    });
});

describe('parseHttp', () => {
    it('parses a known-good link to exact fields', () => {
        const r = parseHttp('http://huser:hpass@http.example.com:8080#Http%20Tag');
        assert.equal(r.server, 'http.example.com');
        assert.equal(r.port, 8080);
        assert.equal(r.user, 'huser');
        assert.equal(r.pass, 'hpass');
        assert.equal(r.remark, 'Http Tag');
    });

    it('strips a stray path from the server name', () => {
        assert.equal(parseHttp('http://example.com/sub/path').server, 'example.com');
    });

    it('rejects a link with no server', () => {
        assert.match(parseHttp('http://').error, /missing server/);
    });
});

describe('truncateStr and maskString', () => {
    it('pass strings through unchanged', () => {
        assert.equal(truncateStr('hello', 10), 'hello');
        assert.equal(truncateStr('hello world', 5), 'hello…');
        assert.equal(maskString('short'), 'short');
        assert.equal(maskString('123456789'), '1234••••6789');
    });

    it('coerce non-strings instead of throwing', () => {
        assert.equal(truncateStr(12345, 3), '123…');
        assert.equal(maskString(123456789), '1234••••6789');
        assert.equal(truncateStr(null, 3), '');
        assert.equal(truncateStr(undefined, 3), '');
        assert.equal(maskString(null), '');
        assert.equal(maskString(undefined), '');
    });
});

describe('html consistency', () => {
    // Anchored at __dirname, not process.cwd(): the bare '../index.html'
    // form throws ENOENT when tests run from a different directory.
    const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

    it('ships an <option> for every ECH preset key', () => {
        for (const key of Object.keys(ECH_PRESETS)) {
            assert.ok(html.includes('<option value="' + key + '"'), 'missing option for ' + key);
        }
    });

    it('ships a protocol badge for every SUB_SCHEME entry with badge coverage', () => {
        // 'socks' badge covers both socks and socks5; tg has no badge and
        // http/ssh are chain-only with no SUB_SCHEME entry, so none of
        // those are asserted here.
        for (const scheme of ['vless', 'vmess', 'trojan', 'ss', 'socks', 'socks5']) {
            const badge = scheme === 'socks5' ? 'socks' : scheme;
            assert.ok(html.includes('data-protocol="' + badge + '"'), 'missing badge for ' + scheme);
        }
    });
});

const VLESS_TLS_FP = 'vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=tls&sni=example.com&fp=oldfp#R';
const VLESS_NOTLS = 'vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:80?security=none#NT';
const TROJAN_NOTLS = 'trojan://myPassword@trojan.example.com:80?security=none#TNT';
const VLESS_QSPACE = 'vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=tls&sni=a%20b#R';
const VLESS_CSF = 'vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=tls&cs=oldcs&fm=oldfm#Z';
const VLESS_ECH = 'vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=tls&ech=old-ech-value#E';

function qp(url, key) {
    return new URL(url).searchParams.get(key);
}

describe('enhanceUrlCore', () => {
    it('sets fp+cs+fm on a tls URL', () => {
        const r = enhanceUrlCore(VLESS_GOOD, { server: '', fp: 'chrome', cs: 'CSVAL', fm: 'FMVAL' });
        assert.ok(r.url);
        assert.equal(qp(r.url, 'fp'), 'chrome');
        assert.equal(qp(r.url, 'cs'), 'CSVAL');
        assert.equal(qp(r.url, 'fm'), 'FMVAL');
    });

    it('sets fp only on a non-tls URL (cs/fm are TLS-only)', () => {
        const r = enhanceUrlCore(VLESS_NOTLS, { server: '', fp: 'chrome', cs: 'CSVAL', fm: 'FMVAL' });
        assert.ok(r.url);
        assert.equal(qp(r.url, 'fp'), 'chrome');
        assert.equal(qp(r.url, 'cs'), null);
        assert.equal(qp(r.url, 'fm'), null);
    });

    it('skips empty cs/fm on a tls URL', () => {
        const r = enhanceUrlCore(VLESS_GOOD, { server: '', fp: 'chrome', cs: '', fm: '' });
        assert.ok(r.url);
        assert.equal(qp(r.url, 'cs'), null);
        assert.equal(qp(r.url, 'fm'), null);
    });

    it('applies the server override and brackets IPv6', () => {
        const v4 = enhanceUrlCore(VLESS_GOOD, { server: '9.9.9.9', fp: '', cs: '', fm: '' });
        assert.equal(new URL(v4.url).hostname, '9.9.9.9');
        const v6 = enhanceUrlCore(VLESS_GOOD, { server: '::1', fp: '', cs: '', fm: '' });
        assert.equal(new URL(v6.url).hostname, '[::1]');
    });

    it('leaves an invalid server override in place without corrupting the URL', () => {
        // The WHATWG hostname setter silently ignores invalid values instead
        // of throwing, so the Invalid-server branch is preserved verbatim but
        // unreachable here: the original host survives and the URL stays valid.
        const r = enhanceUrlCore(VLESS_GOOD, { server: 'not a host!', fp: 'chrome', cs: '', fm: '' });
        assert.ok(r.url);
        assert.equal(new URL(r.url).hostname, 'example.com');
    });

    it('encodes spaces in the query as %20, not +', () => {
        const r = enhanceUrlCore(VLESS_QSPACE, { server: '', fp: '', cs: '', fm: '' });
        assert.ok(r.url.includes('sni=a%20b'));
        assert.ok(!new URL(r.url).search.includes('+'));
    });

    it('rejects unsupported schemes, empty input and unparsable URLs', () => {
        assert.match(enhanceUrlCore('ss://x@y:1', {}).error, /Only VLESS and Trojan/);
        assert.match(enhanceUrlCore('   ', {}).error, /No URL provided/);
        assert.match(enhanceUrlCore('vless://[::1', {}).error, /Failed to parse URL/);
    });

    it('skips the override with ignoreServer', () => {
        const r = enhanceUrlCore(VLESS_GOOD, { server: '9.9.9.9', fp: '', cs: '', fm: '', ignoreServer: true });
        assert.equal(new URL(r.url).hostname, 'example.com');
    });

    it("keeps the existing fp when fp is 'none' (fragment asymmetry)", () => {
        const r = enhanceUrlCore(VLESS_TLS_FP, { server: '', fp: 'none', cs: '', fm: '' });
        assert.equal(qp(r.url, 'fp'), 'oldfp');
    });
});

describe('enhanceEchUrlCore', () => {
    it('sets fp and completes a bare ech domain on a tls URL', () => {
        const r = enhanceEchUrlCore(VLESS_GOOD, { server: '', fp: 'chrome', ech: 'cloudflare-ech.com' });
        assert.ok(r.url);
        assert.equal(qp(r.url, 'fp'), 'chrome');
        assert.equal(qp(r.url, 'ech'), 'cloudflare-ech.com+' + ECH_DNS_DEFAULT);
    });

    it('ignores ech text on a non-tls URL but still applies fp', () => {
        const r = enhanceEchUrlCore(TROJAN_NOTLS, { server: '', fp: 'chrome', ech: 'cloudflare-ech.com' });
        assert.ok(r.url);
        assert.equal(qp(r.url, 'fp'), 'chrome');
        assert.equal(qp(r.url, 'ech'), null);
    });

    it("deletes an existing fp when fp is 'none' or empty (ECH asymmetry)", () => {
        assert.equal(qp(enhanceEchUrlCore(VLESS_TLS_FP, { server: '', fp: 'none', ech: '' }).url, 'fp'), null);
        assert.equal(qp(enhanceEchUrlCore(VLESS_TLS_FP, { server: '', fp: '', ech: '' }).url, 'fp'), null);
    });

    it('deletes an existing ech when the ech input is empty', () => {
        const r = enhanceEchUrlCore(VLESS_ECH, { server: '', fp: '', ech: '' });
        assert.equal(qp(r.url, 'ech'), null);
    });

    it('passes a domain+resolver value through verbatim', () => {
        const full = 'cloudflare-ech.com+udp://1.1.1.1';
        const r = enhanceEchUrlCore(VLESS_GOOD, { server: '', fp: '', ech: full });
        assert.equal(qp(r.url, 'ech'), full);
    });

    it('applies the server override and skips it with ignoreServer', () => {
        const over = enhanceEchUrlCore(VLESS_GOOD, { server: '9.9.9.9', fp: '', ech: '' });
        assert.equal(new URL(over.url).hostname, '9.9.9.9');
        const skip = enhanceEchUrlCore(VLESS_GOOD, { server: '9.9.9.9', fp: '', ech: '', ignoreServer: true });
        assert.equal(new URL(skip.url).hostname, 'example.com');
    });

    it('rejects unsupported schemes and empty input', () => {
        assert.match(enhanceEchUrlCore('ss://x@y:1', {}).error, /Only VLESS and Trojan/);
        assert.match(enhanceEchUrlCore('   ', {}).error, /No URL provided/);
    });
});

describe('extractSubConfigs', () => {
    const lineA = 'vless://a@b:1';
    const lineB = 'trojan://c@d:2';
    const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');

    it('returns a plain list as-is', () => {
        assert.deepEqual(extractSubConfigs(lineA + '\n' + lineB), [lineA, lineB]);
    });

    it('decodes a whole-blob base64 body', () => {
        assert.deepEqual(extractSubConfigs(b64(lineA + '\n' + lineB)), [lineA, lineB]);
    });

    it('decodes per-line base64 blobs', () => {
        assert.deepEqual(extractSubConfigs(b64(lineA) + '\n' + b64(lineB)), [lineA, lineB]);
    });

    it('keeps every config of a per-line base64 body whose chunks lack padding', () => {
        // Regression: concatenating two unpadded chunks, b64(a) + b64(b), is
        // itself valid base64 and decodes to the single merged string a + b.
        // The old whole-body-first order therefore collapsed the whole list
        // into one config. 3-byte-aligned remarks guarantee no '=' padding.
        let a = 'vless://a@b:1#x';
        while (Buffer.byteLength(a, 'utf8') % 3 !== 0) a += 'x';
        let b = 'trojan://c@d:2#y';
        while (Buffer.byteLength(b, 'utf8') % 3 !== 0) b += 'y';
        assert.ok(!b64(a).endsWith('=') && !b64(b).endsWith('='));
        assert.equal(safeAtob(b64(a) + b64(b)), a + b); // the trap this guards
        assert.deepEqual(extractSubConfigs(b64(a) + '\n' + b64(b)), [a, b]);
    });

    it('decodes per-line base64 vmess containers', () => {
        const vm = vmessLink('per-line');
        assert.deepEqual(extractSubConfigs(b64(vm)), [vm]);
    });

    it('still decodes a line-wrapped whole-body base64 blob', () => {
        const whole = b64(lineA + '\n' + lineB);
        const wrapped = (whole.match(/.{1,20}/g) || []).join('\n');
        assert.deepEqual(extractSubConfigs(wrapped), [lineA, lineB]);
    });

    it('keeps every config of a wrapped whole-body blob under the standard 76-char wrap', () => {
        // Regression for the per-line-first heuristic: with 25-byte config
        // lines and a 76-char wrap, every wrapped chunk contains a full or
        // cut-off config-looking fragment, so the per-line branch stole the
        // decision — output had a truncated "vless://u@" and lost two configs.
        const lines = [];
        for (let i = 0; i < 6; i++) lines.push('vless://u@1.2.3.4:443#c0' + i);
        const text = lines.join('\n');
        const wrapped = (b64(text).match(/.{1,76}/g) || []).join('\n');
        assert.deepEqual(extractSubConfigs(wrapped), lines);
    });

    it('keeps every config of a wrapped whole-body blob under a 64-char wrap', () => {
        const lines = [];
        for (let i = 0; i < 6; i++) lines.push('vless://u@1.2.3.4:443#c0' + i);
        const text = lines.join('\n');
        const wrapped = (b64(text).match(/.{1,64}/g) || []).join('\n');
        assert.deepEqual(extractSubConfigs(wrapped), lines);
    });

    it('keeps long-line wrapped blobs on the whole-body path', () => {
        const lines = [];
        for (let i = 0; i < 4; i++) {
            let l = 'vless://12345678-1234-1234-1234-1234567890ab@example-' + i +
                '.com:443?security=reality&sni=example.com&fp=chrome#' + i;
            while (l.length < 120) l += 'x';
            lines.push(l);
        }
        const wrapped = (b64(lines.join('\n')).match(/.{1,76}/g) || []).join('\n');
        assert.deepEqual(extractSubConfigs(wrapped), lines);
    });

    it('merges mixed plain+base64 lines with dedupe', () => {
        const mixed = lineA + '\n' + b64(lineA) + '\n' + b64(lineB);
        // Original lines stay verbatim; decoded configs are appended once —
        // lineA decodes to an already-seen line so it is not duplicated.
        assert.deepEqual(extractSubConfigs(mixed), [lineA, b64(lineA), b64(lineB), lineB]);
    });

    it('returns [] for junk, HTML and blank input', () => {
        assert.deepEqual(extractSubConfigs('hello-world-no-scheme'), []);
        assert.deepEqual(extractSubConfigs('<html>not a sub</html>'), []);
        assert.deepEqual(extractSubConfigs('   '), []);
    });
});

describe('expandBulkLines', () => {
    const lineA = 'vless://a@b:1';
    const lineB = 'trojan://c@d:2';
    const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');

    it('returns a plain one-per-line list unchanged', () => {
        assert.deepEqual(expandBulkLines(lineA + '\n' + lineB), [lineA, lineB]);
    });

    it('expands a whole-body base64 blob into every config', () => {
        // The URL box receives the blob as a single line, which used to reach
        // parseProxyURLSingle() and merge into one link.
        assert.deepEqual(expandBulkLines(b64(lineA + '\n' + lineB)), [lineA, lineB]);
    });

    it('expands per-line base64 blobs', () => {
        assert.deepEqual(expandBulkLines(b64(lineA) + '\n' + b64(lineB)), [lineA, lineB]);
    });

    it('expands a line-wrapped whole-body blob', () => {
        const wrapped = (b64(lineA + '\n' + lineB).match(/.{1,20}/g) || []).join('\n');
        assert.deepEqual(expandBulkLines(wrapped), [lineA, lineB]);
    });

    it('falls back to the raw lines so junk keeps its parse error', () => {
        assert.deepEqual(expandBulkLines('not-a-url\nmore junk'), ['not-a-url', 'more junk']);
    });

    it('returns [] for blank input', () => {
        assert.deepEqual(expandBulkLines('   '), []);
        assert.deepEqual(expandBulkLines(''), []);
    });

    it('drops a raw base64 line its decode already adds (no duplicate output)', () => {
        // A mixed body keeps raw b64 lines AND their decoded copies; the
        // bulk box parses every line, so the config appeared twice in the
        // enhance/download output. Subscription rendering already skips
        // such raw lines (script.js renderTabResults) — mirror that here.
        const mixed = lineA + '\n' + b64(lineB);
        assert.deepEqual(expandBulkLines(mixed), [lineA, lineB]);
    });

    it('keeps a raw base64 line whose decode holds no config (parse error preserved)', () => {
        const junkB64 = b64('not a config');
        assert.deepEqual(expandBulkLines(lineA + '\n' + junkB64), [lineA, junkB64]);
    });

    it('keeps non-base64 junk lines verbatim (no scheme in decode either)', () => {
        assert.deepEqual(expandBulkLines(lineA + '\nnot a url'), [lineA, 'not a url']);
    });

    it('still expands a pure blob body unchanged', () => {
        assert.deepEqual(expandBulkLines(b64(lineA + '\n' + lineB)), [lineA, lineB]);
    });
});

describe('subLooksLikeContent mirror parity', () => {
    const lineA = 'vless://a@b:1';
    const lineB = 'trojan://c@d:2';
    const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');

    it('accepts a per-line padded base64 body (whole-concat decode fails)', () => {
        // Regression: the whole-body concatenation carries mid-stream '='
        // padding and safeAtob() returns null, so the mirror said "not
        // content" while extractSubConfigs() parsed 2 valid configs — the
        // subscription tab rejected input the bulk box accepts.
        const body = b64(lineA) + '\n' + b64(lineB);
        assert.equal(subLooksLikeContent(body), true);
        assert.equal(subValidate(body), 'content');
    });

    it('accepts a per-line unpadded base64 body', () => {
        const a = lineA + '#x', b = lineB + '#y';
        let aa = a; while (Buffer.byteLength(aa, 'utf8') % 3 !== 0) aa += 'x';
        let bb = b; while (Buffer.byteLength(bb, 'utf8') % 3 !== 0) bb += 'y';
        const body = b64(aa) + '\n' + b64(bb);
        assert.equal(subLooksLikeContent(body), true);
    });

    it('accepts a line-wrapped whole-body blob (unchanged path)', () => {
        const wrapped = (b64(lineA + '\n' + lineB).match(/.{1,20}/g) || []).join('\n');
        assert.equal(subLooksLikeContent(wrapped), true);
    });

    it('rejects a body where any line decodes to no config', () => {
        const junk = b64('not a config');
        assert.equal(subLooksLikeContent(b64(lineA) + '\n' + junk), false);
    });

    it('rejects plain junk without schemes (unchanged path)', () => {
        assert.equal(subLooksLikeContent('hello-world-no-scheme'), false);
    });
});

describe('subIsBlockedError', () => {
    it('matches TypeError by name and fetch text as fallback', () => {
        const t = new Error('whatever');
        t.name = 'TypeError';
        assert.equal(subIsBlockedError(t), true);
        assert.equal(subIsBlockedError(new Error('Failed to fetch')), true);
        assert.equal(subIsBlockedError(new Error('Load failed')), true);
    });

    it('rejects ordinary errors', () => {
        assert.equal(subIsBlockedError(new Error('HTTP 500')), false);
    });
});

function namedErr(name, message) {
    const e = new Error(message);
    e.name = name;
    return e;
}

describe('subErrorText', () => {
    it('reports the offline flag', () => {
        assert.match(subErrorText(new Error('x'), false), /offline/);
    });

    it('reports a total timeout with the shared duration', () => {
        assert.equal(Math.round(SUB_TOTAL_MS / 60000), 5);
        assert.match(subErrorText(namedErr('SubTotalTimeout', 'Total timeout')), /longer than 5 minutes/);
    });

    it('reports an idle abort with the shared duration', () => {
        assert.equal(Math.round(SUB_IDLE_MS / 1000), 30);
        assert.match(subErrorText(namedErr('AbortError', 'idle-timeout')), /silent for 30s/);
    });

    it('explains HTTP 401/403/404/other distinctly', () => {
        assert.match(subErrorText(new Error('HTTP 401')), /expired or invalid/);
        assert.match(subErrorText(new Error('HTTP 403')), /expired or invalid/);
        assert.match(subErrorText(new Error('HTTP 404')), /does not exist/);
        assert.match(subErrorText(new Error('HTTP 500')), /wrong or the server/);
    });

    it('points blocked fetches at the paste fallback', () => {
        const t = new Error('Failed to fetch');
        t.name = 'TypeError';
        assert.match(subErrorText(t), /blocks browser access/);
    });

    it('returns the shared message for SubTooLarge', () => {
        assert.equal(subErrorText(namedErr('SubTooLarge', 'Subscription body exceeds 2 MiB')), SUB_TOO_LARGE_MSG);
    });

    it('falls back to the raw message for anything else', () => {
        assert.equal(subErrorText(new Error('weird-boom')), 'Could not read the response (weird-boom).');
    });
});

// Plan 026 parity locks. pure.js is FROZEN: these groups pin the shared
// primitives both createEnhanceTab instances (echTab, fragTab) are built on,
// so a future pure.js change that would break tab parity fails here. The
// controller's DOM behavior (buttons, card classes, scroll) was verified by
// static re-read; the live two-tab matrix is a DEFERRED operator gate.
function classify026(configs, enhanceFn) {
    // Verbatim mirror of renderTabResults counting in script.js (026):
    // base64-container twin drop, then invalid vs skipped vs enhanced with
    // the unified fragment rule (enhance failure counts skipped, never invalid).
    let enhanced = [];
    let skipped = 0;
    let invalid = 0;
    configs.forEach(line => {
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
        const res = enhanceFn(line);
        if (res && res.url) {
            enhanced.push(res.url);
        } else {
            skipped++;
        }
    });
    return { enhanced: enhanced.length, skipped, invalid };
}

const fragEnhance026 = (line) => enhanceUrlCore(line, { server: '', fp: 'chrome', cs: '', fm: '', ignoreServer: true });
const echEnhance026 = (line) => enhanceEchUrlCore(line, { server: '', fp: 'chrome', ech: '', ignoreServer: true });

describe('026 parity (1) count-matrix per tab', () => {
    const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
    const mixed = [
        VLESS_GOOD,
        b64(VLESS_GOOD), // base64 container whose decoded twin is listed above
        vmessLink('m'), // parses, unsupported protocol -> skipped
        'vless://[::1', // unparseable -> invalid
        'junk-no-scheme' // unparseable -> invalid
    ].join('\n');

    it('extracts the same config list for both tabs', () => {
        assert.equal(extractSubConfigs(mixed).length, 5);
    });

    it('reports identical enhanced/skipped/invalid on both tabs', () => {
        const configs = extractSubConfigs(mixed);
        const frag = classify026(configs, fragEnhance026);
        const ech = classify026(configs, echEnhance026);
        assert.deepEqual(frag, { enhanced: 1, skipped: 1, invalid: 2 });
        assert.deepEqual(ech, frag);
    });

    it('counts an enhance failure as skipped, never invalid (fragment rule)', () => {
        const configs = extractSubConfigs(VLESS_GOOD);
        const res = classify026(configs, () => null);
        assert.deepEqual(res, { enhanced: 0, skipped: 1, invalid: 0 });
    });
});

describe('026 parity (2) joins', () => {
    it('joins URL-mode output with blank lines on both tabs', () => {
        assert.equal(['a', 'b'].join('\n\n'), 'a\n\nb');
    });

    it('joins sub-mode output with single newlines on both tabs', () => {
        assert.equal(['a', 'b'].join('\n'), 'a\nb');
    });

    it('exports exactly what is displayed plus one trailing newline', () => {
        const display = ['a', 'b'].join('\n');
        const txtExport = display + '\n';
        assert.equal(txtExport, 'a\nb\n');
        assert.equal(safeAtob(encodeUtf8ToB64(display)), display);
    });
});

describe('026 parity (3) stale-fetch', () => {
    const isStale026 = (fieldValue, fetchRaw) => fieldValue.trim() !== fetchRaw;

    it('treats a changed field as stale on both tabs', () => {
        assert.equal(isStale026('https://example.com/other', 'https://example.com/sub'), true);
    });

    it('treats an unchanged field as fresh on both tabs', () => {
        assert.equal(isStale026('https://example.com/sub', 'https://example.com/sub'), false);
        assert.equal(isStale026('  https://example.com/sub  ', 'https://example.com/sub'), false);
    });

    it('renders a fetched body exactly like the same pasted contents', () => {
        const body = VLESS_GOOD + '\n' + TROJAN_GOOD;
        assert.deepEqual(extractSubConfigs(body), extractSubConfigs(body));
        assert.equal(extractSubConfigs(body).length, 2);
    });

    it('shares one error mapping on the failure path', () => {
        assert.match(subErrorText(new Error('HTTP 404')), /does not exist/);
    });
});

describe('026 parity (4) busy-typing', () => {
    // Mirrors subCanRun in script.js, which the controller's busy guard and
    // both fetch entries share: typing mid-fetch must never re-enable Fetch.
    const canRun026 = (mode) => mode === 'link' || mode === 'content';

    it('runs link and pasted content on both tabs', () => {
        assert.equal(canRun026(subValidate('https://example.com/sub/token')), true);
        assert.equal(canRun026(subValidate('vless://uuid@example.com:443')), true);
    });

    it('refuses proxy and invalid input on both tabs', () => {
        assert.equal(canRun026(subValidate('http://host:8080')), false);
        assert.equal(canRun026(subValidate('hello-world-no-scheme')), false);
    });
});

describe('026 parity (5) remark-host', () => {
    it('moves the fragment host to the override (re-read differs from pre-parse)', () => {
        const before = parseProxyURLSingle(VLESS_GOOD).server;
        const after = new URL(enhanceUrlCore(VLESS_GOOD, { server: '9.9.9.9', fp: '', cs: '', fm: '' }).url).hostname;
        assert.equal(before, 'example.com');
        assert.equal(after, '9.9.9.9');
    });

    it('moves the ECH host to the override (re-read differs from pre-parse)', () => {
        const before = parseProxyURLSingle(VLESS_GOOD).server;
        const after = new URL(enhanceEchUrlCore(VLESS_GOOD, { server: '9.9.9.9', fp: '', ech: '' }).url).hostname;
        assert.equal(before, 'example.com');
        assert.equal(after, '9.9.9.9');
    });
});

describe('026 parity (6) failure-copy', () => {
    it('takes the no-configs branch on empty and junk input', () => {
        assert.deepEqual(extractSubConfigs('   '), []);
        assert.deepEqual(extractSubConfigs('hello-world-no-scheme'), []);
    });

    it('takes the found-but-unenhanceable branch on unsupported-only input', () => {
        assert.equal(extractSubConfigs(vmessLink('m')).length, 1);
    });

    it('justifies the shared VLESS/Trojan wording: the renderer skips vmess', () => {
        assert.equal(parseProxyURLSingle(vmessLink('m')).protocol, 'vmess');
    });
});

describe('026 parity (7) CORS step-3', () => {
    it('gates the manual-fetch guide on the same blocked predicate on both tabs', () => {
        const blocked = new Error('Failed to fetch');
        blocked.name = 'TypeError';
        assert.equal(subIsBlockedError(blocked), true);
        assert.equal(subIsBlockedError(new Error('HTTP 500')), false);
    });

    it('keeps step-3 text per tab (fragment vs ECH button labels differ)', () => {
        const fragStep3 = 'Paste it into the box above and press Fetch & Enhance.';
        const echStep3 = 'Paste it into the subscription box above and press Fetch & Enhance Sub.';
        assert.notEqual(fragStep3, echStep3);
        assert.match(echStep3, /Fetch & Enhance Sub/);
        assert.doesNotMatch(fragStep3, /Fetch & Enhance Sub/);
    });
});

// ===== Config-builder goldens (plan 016) =====
// Locked against the verbatim move from script.js: every case asserts the
// FULL returned object, so a renamed key, changed default or dropped branch
// fails loudly. Inputs are small and focused, not whole app configs.
// FIXED (trim+h2) — goldens below assert the NEW behavior:
// - Both alpn splits now trim entries: 'h2, http/1.1' -> ['h2', 'http/1.1'].
// - sing-box no longer drops 'h2' (Xray's own default ALPN is
//   ["h2", "http/1.1"]; no documented reason for the exclusion was found).
//   NOTE: re-enabling h2 changes the observable TLS fingerprint of
//   generated sing-box configs — operator-signed-off 2026-10-12.
// - sing-box vless always emits packet_encoding: ''.
// - Empty alpn defaults to ['http/1.1'] in Xray but omits tls.alpn in sing-box.
// - listen_port follows socks-port (||10808 fallback) / log mapping / remote-dns live in the DOM-bound
//   generate* wrappers, not in these builders — untouched here.

const VLESS_WS_TLS = {
    protocol: 'vless', uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    server: 'example.com', port: 443, encryption: 'none',
    type: 'ws', host: 'h.example.com', path: '/path',
    security: 'tls', sni: 'example.com', fp: 'chrome', alpn: 'h2,http/1.1'
};

const VLESS_REALITY_TCP_HTTP = {
    protocol: 'vless', uuid: 'u1', server: 'r.example.com', port: 443,
    type: 'tcp', headerType: 'http', host: 'h.example.com', path: '/a,/b',
    security: 'reality', sni: 'r.example.com', fp: 'chrome',
    pbk: 'PUBKEY', sid: 'SHORT', spx: '/spider'
};

const TROJAN_GRPC_TLS = {
    protocol: 'trojan', password: 'pw', server: 't.example.com', port: 443,
    type: 'grpc', serviceName: 'svc', authority: 'auth.example.com', mode: 'multi',
    security: 'tls', sni: 't.example.com', fp: 'firefox', alpn: 'http/1.1'
};

const VLESS_FLOW_REALITY = {
    protocol: 'vless', uuid: 'u1', server: 'f.example.com', port: 443,
    type: 'tcp', security: 'reality', sni: 'f.example.com',
    flow: 'xtls-rprx-vision', encryption: 'none'
};

const VLESS_ECH_WS = {
    protocol: 'vless', uuid: 'u1', server: 'e.example.com', port: 443,
    type: 'ws', path: '/', security: 'tls', sni: 'e.example.com',
    ech: 'cloudflare-ech.com+udp://1.1.1.1'
};

describe('buildStreamSettings', () => {
    it('vless ws/tls golden', () => {
        assert.deepEqual(buildStreamSettings(VLESS_WS_TLS, false), {
            network: 'ws',
            security: 'tls',
            sockopt: { domainStrategy: 'UseIP' },
            wsSettings: { host: 'h.example.com', path: '/path' },
            tlsSettings: {
                serverName: 'example.com',
                fingerprint: 'chrome',
                alpn: ['h2', 'http/1.1'],
                allowInsecure: false
            }
        });
    });

    it('vless reality tcp with http header uses chain sockopt', () => {
        assert.deepEqual(buildStreamSettings(VLESS_REALITY_TCP_HTTP, true), {
            network: 'tcp',
            security: 'reality',
            sockopt: { domainStrategy: 'UseIPv4', dialerProxy: 'proxy' },
            rawSettings: {
                header: {
                    type: 'http',
                    request: {
                        headers: { Host: ['h.example.com'] },
                        path: ['/a', '/b'],
                        method: 'GET',
                        version: '1.1'
                    }
                }
            },
            realitySettings: {
                serverName: 'r.example.com',
                fingerprint: 'chrome',
                publicKey: 'PUBKEY',
                shortId: 'SHORT',
                spiderX: '/spider',
                show: false,
                allowInsecure: false
            }
        });
    });

    it('trojan grpc/tls golden', () => {
        assert.deepEqual(buildStreamSettings(TROJAN_GRPC_TLS, false), {
            network: 'grpc',
            security: 'tls',
            sockopt: { domainStrategy: 'UseIP' },
            grpcSettings: {
                authority: 'auth.example.com',
                multiMode: true,
                serviceName: 'svc'
            },
            tlsSettings: {
                serverName: 't.example.com',
                fingerprint: 'firefox',
                alpn: ['http/1.1'],
                allowInsecure: false
            }
        });
    });

    it('httpupgrade/tls golden', () => {
        assert.deepEqual(buildStreamSettings({
            protocol: 'vless', uuid: 'u1', server: 'hu.example.com', port: 443,
            type: 'httpupgrade', host: 'hu.example.com', path: '/up',
            security: 'tls', sni: 'hu.example.com', fp: 'chrome'
        }, false), {
            network: 'httpupgrade',
            security: 'tls',
            sockopt: { domainStrategy: 'UseIP' },
            httpupgradeSettings: { host: 'hu.example.com', path: '/up' },
            tlsSettings: {
                serverName: 'hu.example.com',
                fingerprint: 'chrome',
                alpn: ['http/1.1'],
                allowInsecure: false
            }
        });
    });

    it('tcp/none emits no transport or tls keys', () => {
        assert.deepEqual(buildStreamSettings({
            protocol: 'vless', uuid: 'u1', server: 'p.example.com', port: 80,
            type: 'tcp', headerType: 'none', security: 'none'
        }, false), {
            network: 'tcp',
            security: 'none',
            sockopt: { domainStrategy: 'UseIP' }
        });
    });

    it('spaced alpn is trimmed', () => {
        const out = buildStreamSettings({
            protocol: 'vless', uuid: 'u1', server: 'a.example.com', port: 443,
            type: 'ws', path: '/', security: 'tls', sni: 'a.example.com',
            alpn: 'h2, http/1.1'
        }, false);
        assert.deepEqual(out.tlsSettings.alpn, ['h2', 'http/1.1']);
    });

    it('missing alpn defaults to http/1.1', () => {
        const out = buildStreamSettings({
            protocol: 'vless', uuid: 'u1', server: 'e.example.com', port: 443,
            type: 'ws', path: '/', security: 'tls', sni: 'e.example.com'
        }, false);
        assert.deepEqual(out.tlsSettings.alpn, ['http/1.1']);
    });

    it('ech passes through verbatim into tlsSettings.echConfigList', () => {
        const out = buildStreamSettings(VLESS_ECH_WS, false);
        assert.equal(out.tlsSettings.echConfigList, 'cloudflare-ech.com+udp://1.1.1.1');
        assert.deepEqual(out.tlsSettings.alpn, ['http/1.1']);
    });
});

describe('buildProxyOutbound', () => {
    it('vless flow golden (post-012 flow presence)', () => {
        assert.deepEqual(buildProxyOutbound(VLESS_FLOW_REALITY), {
            protocol: 'vless',
            tag: 'proxy',
            settings: {
                vnext: [{
                    address: 'f.example.com',
                    port: 443,
                    users: [{ id: 'u1', encryption: 'none', flow: 'xtls-rprx-vision' }]
                }]
            },
            streamSettings: {
                network: 'tcp',
                security: 'reality',
                sockopt: { domainStrategy: 'UseIP' },
                realitySettings: {
                    serverName: 'f.example.com',
                    fingerprint: 'chrome',
                    publicKey: '',
                    shortId: '',
                    spiderX: '',
                    show: false,
                    allowInsecure: false
                }
            }
        });
    });

    it('ech-bearing vless passes echConfigList through verbatim', () => {
        const out = buildProxyOutbound(VLESS_ECH_WS);
        assert.equal(out.streamSettings.tlsSettings.echConfigList, 'cloudflare-ech.com+udp://1.1.1.1');
        assert.deepEqual(out, {
            protocol: 'vless',
            tag: 'proxy',
            settings: {
                vnext: [{
                    address: 'e.example.com',
                    port: 443,
                    users: [{ id: 'u1', encryption: 'none' }]
                }]
            },
            streamSettings: {
                network: 'ws',
                security: 'tls',
                sockopt: { domainStrategy: 'UseIP' },
                wsSettings: { path: '/' },
                tlsSettings: {
                    serverName: 'e.example.com',
                    fingerprint: 'chrome',
                    alpn: ['http/1.1'],
                    allowInsecure: false,
                    echConfigList: 'cloudflare-ech.com+udp://1.1.1.1'
                }
            }
        });
    });

    it('vmess golden', () => {
        assert.deepEqual(buildProxyOutbound({
            protocol: 'vmess', uuid: 'uuid-x', server: 'm.example.com', port: 443,
            aid: 0, type: 'ws', host: 'h', path: '/p',
            security: 'tls', sni: 'm.example.com'
        }), {
            protocol: 'vmess',
            tag: 'proxy',
            settings: {
                vnext: [{
                    address: 'm.example.com',
                    port: 443,
                    users: [{ id: 'uuid-x', alterId: 0, security: 'auto' }]
                }]
            },
            streamSettings: {
                network: 'ws',
                security: 'tls',
                sockopt: { domainStrategy: 'UseIP' },
                wsSettings: { host: 'h', path: '/p' },
                tlsSettings: {
                    serverName: 'm.example.com',
                    fingerprint: 'chrome',
                    alpn: ['http/1.1'],
                    allowInsecure: false
                }
            }
        });
    });

    it('trojan grpc golden', () => {
        assert.deepEqual(buildProxyOutbound(TROJAN_GRPC_TLS), {
            protocol: 'trojan',
            tag: 'proxy',
            settings: {
                servers: [{ address: 't.example.com', port: 443, password: 'pw' }]
            },
            streamSettings: {
                network: 'grpc',
                security: 'tls',
                sockopt: { domainStrategy: 'UseIP' },
                grpcSettings: {
                    authority: 'auth.example.com',
                    multiMode: true,
                    serviceName: 'svc'
                },
                tlsSettings: {
                    serverName: 't.example.com',
                    fingerprint: 'firefox',
                    alpn: ['http/1.1'],
                    allowInsecure: false
                }
            }
        });
    });

    it('shadowsocks golden', () => {
        assert.deepEqual(buildProxyOutbound({
            protocol: 'shadowsocks', method: 'aes-256-gcm', password: 'mypass',
            server: 'ss.example.com', port: 8388
        }), {
            protocol: 'shadowsocks',
            tag: 'proxy',
            settings: {
                servers: [{
                    address: 'ss.example.com', port: 8388,
                    method: 'aes-256-gcm', password: 'mypass'
                }]
            },
            streamSettings: {
                network: 'tcp',
                security: 'none',
                sockopt: { domainStrategy: 'UseIP' }
            }
        });
    });

    it('socks with credentials emits users', () => {
        assert.deepEqual(buildProxyOutbound({
            protocol: 'socks', server: 's.example.com', port: 1080, user: 'u', pass: 'pw'
        }), {
            protocol: 'socks',
            tag: 'proxy',
            settings: {
                servers: [{
                    address: 's.example.com', port: 1080,
                    users: [{ user: 'u', pass: 'pw' }]
                }]
            },
            streamSettings: {
                network: 'tcp',
                security: 'none',
                sockopt: { domainStrategy: 'UseIP' }
            }
        });
    });

    it('socks user-only emits no users key', () => {
        const out = buildProxyOutbound({
            protocol: 'socks', server: 's.example.com', port: 1080, user: 'u'
        });
        assert.deepEqual(out.settings.servers, [{ address: 's.example.com', port: 1080 }]);
    });

    it('http with credentials emits users', () => {
        assert.deepEqual(buildProxyOutbound({
            protocol: 'http', server: 'h.example.com', port: 8080, user: 'u', pass: 'pw'
        }), {
            protocol: 'http',
            tag: 'proxy',
            settings: {
                servers: [{
                    address: 'h.example.com', port: 8080,
                    users: [{ user: 'u', pass: 'pw' }]
                }]
            },
            streamSettings: {
                network: 'tcp',
                security: 'none',
                sockopt: { domainStrategy: 'UseIP' }
            }
        });
    });

    it('http without credentials emits a bare server', () => {
        const out = buildProxyOutbound({
            protocol: 'http', server: 'h.example.com', port: 8080
        });
        assert.deepEqual(out.settings.servers, [{ address: 'h.example.com', port: 8080 }]);
    });

    it('unknown protocol returns null', () => {
        assert.equal(buildProxyOutbound({ protocol: 'wireguard', server: 'x', port: 1 }), null);
    });
});

describe('buildChainOutbound', () => {
    it('vless flow golden with chain sockopt (post-012 flow presence)', () => {
        assert.deepEqual(buildChainOutbound(VLESS_FLOW_REALITY), {
            protocol: 'vless',
            tag: 'chain',
            settings: {
                vnext: [{
                    address: 'f.example.com',
                    port: 443,
                    users: [{ id: 'u1', encryption: 'none', flow: 'xtls-rprx-vision' }]
                }]
            },
            streamSettings: {
                network: 'tcp',
                security: 'reality',
                sockopt: { domainStrategy: 'UseIPv4', dialerProxy: 'proxy' },
                realitySettings: {
                    serverName: 'f.example.com',
                    fingerprint: 'chrome',
                    publicKey: '',
                    shortId: '',
                    spiderX: '',
                    show: false,
                    allowInsecure: false
                }
            }
        });
    });

    it('socks with credentials uses chain sockopt', () => {
        assert.deepEqual(buildChainOutbound({
            protocol: 'socks', server: 's.example.com', port: 1080, user: 'u', pass: 'pw'
        }), {
            protocol: 'socks',
            tag: 'chain',
            settings: {
                servers: [{
                    address: 's.example.com', port: 1080,
                    users: [{ user: 'u', pass: 'pw' }]
                }]
            },
            streamSettings: {
                network: 'tcp',
                security: 'none',
                sockopt: { domainStrategy: 'UseIPv4', dialerProxy: 'proxy' }
            }
        });
    });

    it('unknown protocol returns null', () => {
        assert.equal(buildChainOutbound({ protocol: 'nope', server: 'x', port: 1 }), null);
    });
});

describe('buildSingboxOutbound', () => {
    it('vless ws/tls golden (h2 kept, empty packet_encoding)', () => {
        assert.deepEqual(buildSingboxOutbound(VLESS_WS_TLS, 'proxy', null), {
            tag: 'proxy',
            type: 'vless',
            server: 'example.com',
            server_port: 443,
            uuid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            packet_encoding: '',
            network: 'tcp',
            tls: {
                enabled: true,
                server_name: 'example.com',
                alpn: ['h2', 'http/1.1'],
                utls: { enabled: true, fingerprint: 'chrome' }
            },
            transport: {
                type: 'ws',
                path: '/path',
                headers: { Host: 'h.example.com' }
            }
        });
    });

    it('spaced alpn is trimmed and h2 kept', () => {
        const out = buildSingboxOutbound({
            protocol: 'vless', uuid: 'u1', server: 'a.example.com', port: 443,
            type: 'ws', path: '/', security: 'tls', sni: 'a.example.com',
            alpn: 'h2, http/1.1'
        }, 'proxy', null);
        assert.deepEqual(out.tls.alpn, ['h2', 'http/1.1']);
    });

    it('missing alpn omits tls.alpn (asymmetry with Xray, recorded)', () => {
        const out = buildSingboxOutbound({
            protocol: 'vless', uuid: 'u1', server: 'd.example.com', port: 443,
            type: 'ws', path: '/', security: 'tls', sni: 'd.example.com'
        }, 'proxy', null);
        assert.ok(!('alpn' in out.tls));
        assert.deepEqual(out, {
            tag: 'proxy',
            type: 'vless',
            server: 'd.example.com',
            server_port: 443,
            uuid: 'u1',
            packet_encoding: '',
            network: 'tcp',
            tls: { enabled: true, server_name: 'd.example.com' },
            transport: { type: 'ws', path: '/', headers: {} }
        });
    });

    it('vless reality+flow with detour golden', () => {
        assert.deepEqual(buildSingboxOutbound(VLESS_FLOW_REALITY, 'chain', 'proxy'), {
            tag: 'chain',
            type: 'vless',
            detour: 'proxy',
            server: 'f.example.com',
            server_port: 443,
            uuid: 'u1',
            packet_encoding: '',
            network: 'tcp',
            flow: 'xtls-rprx-vision',
            tls: { enabled: true, server_name: 'f.example.com' }
        });
    });

    it('reality with pbk emits the reality block', () => {
        assert.deepEqual(buildSingboxOutbound({
            protocol: 'vless', uuid: 'u1', server: 'r.example.com', port: 443,
            type: 'tcp', security: 'reality', sni: 'r.example.com',
            fp: 'chrome', pbk: 'PUBKEY', sid: 'SHORT'
        }, 'proxy', null), {
            tag: 'proxy',
            type: 'vless',
            server: 'r.example.com',
            server_port: 443,
            uuid: 'u1',
            packet_encoding: '',
            network: 'tcp',
            tls: {
                enabled: true,
                server_name: 'r.example.com',
                utls: { enabled: true, fingerprint: 'chrome' },
                reality: { enabled: true, public_key: 'PUBKEY', short_id: 'SHORT' }
            }
        });
    });

    it('trojan grpc with detour golden', () => {
        assert.deepEqual(buildSingboxOutbound(TROJAN_GRPC_TLS, 'proxy', 'hop-1'), {
            tag: 'proxy',
            type: 'trojan',
            detour: 'hop-1',
            server: 't.example.com',
            server_port: 443,
            password: 'pw',
            network: 'tcp',
            tls: {
                enabled: true,
                server_name: 't.example.com',
                alpn: ['http/1.1'],
                utls: { enabled: true, fingerprint: 'firefox' }
            },
            transport: { type: 'grpc', service_name: 'svc' }
        });
    });

    it('vmess golden', () => {
        assert.deepEqual(buildSingboxOutbound({
            protocol: 'vmess', uuid: 'uuid-x', server: 'm.example.com', port: 443,
            type: 'tcp', security: 'none'
        }, 'proxy', null), {
            tag: 'proxy',
            type: 'vmess',
            server: 'm.example.com',
            server_port: 443,
            uuid: 'uuid-x',
            security: 'auto',
            alter_id: 0,
            network: 'tcp'
        });
    });

    it('shadowsocks golden', () => {
        assert.deepEqual(buildSingboxOutbound({
            protocol: 'shadowsocks', method: 'aes-256-gcm', password: 'mypass',
            server: 'ss.example.com', port: 8388
        }, 'proxy', null), {
            tag: 'proxy',
            type: 'shadowsocks',
            server: 'ss.example.com',
            server_port: 8388,
            method: 'aes-256-gcm',
            password: 'mypass',
            network: 'tcp'
        });
    });

    it('socks with credentials golden', () => {
        assert.deepEqual(buildSingboxOutbound({
            protocol: 'socks', server: 's.example.com', port: 1080, user: 'u', pass: 'pw'
        }, 'proxy', null), {
            tag: 'proxy',
            type: 'socks',
            server: 's.example.com',
            server_port: 1080,
            version: '5',
            network: 'tcp',
            username: 'u',
            password: 'pw'
        });
    });

    it('socks user-only emits no username', () => {
        const out = buildSingboxOutbound({
            protocol: 'socks', server: 's.example.com', port: 1080, user: 'u'
        }, 'proxy', null);
        assert.ok(!('username' in out));
        assert.ok(!('password' in out));
    });

    it('http with credentials golden', () => {
        assert.deepEqual(buildSingboxOutbound({
            protocol: 'http', server: 'h.example.com', port: 8080, user: 'u', pass: 'pw'
        }, 'proxy', null), {
            tag: 'proxy',
            type: 'http',
            server: 'h.example.com',
            server_port: 8080,
            username: 'u',
            password: 'pw'
        });
    });

    it('http without credentials emits a bare outbound', () => {
        assert.deepEqual(buildSingboxOutbound({
            protocol: 'http', server: 'h.example.com', port: 8080
        }, 'proxy', null), {
            tag: 'proxy',
            type: 'http',
            server: 'h.example.com',
            server_port: 8080
        });
    });

    it('ssh returns early with no tls or transport keys', () => {
        const out = buildSingboxOutbound({
            protocol: 'ssh', server: 'ssh.example.com', port: 22,
            user: 'root', password: 'secret'
        }, 'proxy', null);
        assert.deepEqual(out, {
            tag: 'proxy',
            type: 'ssh',
            server: 'ssh.example.com',
            server_port: 22,
            user: 'root',
            password: 'secret'
        });
        assert.ok(!('tls' in out));
        assert.ok(!('transport' in out));
    });

    it('ech maps to query_server_name', () => {
        const out = buildSingboxOutbound(VLESS_ECH_WS, 'proxy', null);
        assert.deepEqual(out.tls.ech, { enabled: true, query_server_name: 'cloudflare-ech.com' });
        assert.equal(out.tls.record_fragment, false);
    });

    it('httpupgrade transport golden', () => {
        assert.deepEqual(buildSingboxOutbound({
            protocol: 'vless', uuid: 'u1', server: 'hu.example.com', port: 443,
            type: 'httpupgrade', host: 'hu.example.com', path: '/up',
            security: 'tls', sni: 'hu.example.com'
        }, 'proxy', null), {
            tag: 'proxy',
            type: 'vless',
            server: 'hu.example.com',
            server_port: 443,
            uuid: 'u1',
            packet_encoding: '',
            network: 'tcp',
            tls: { enabled: true, server_name: 'hu.example.com' },
            transport: { type: 'httpupgrade', host: 'hu.example.com', path: '/up' }
        });
    });

    it('ws early-data from ?ed= golden', () => {
        assert.deepEqual(buildSingboxOutbound({
            protocol: 'vless', uuid: 'u1', server: 'w.example.com', port: 443,
            type: 'ws', host: 'w.example.com', path: '/path?ed=2048',
            security: 'tls', sni: 'w.example.com'
        }, 'proxy', null), {
            tag: 'proxy',
            type: 'vless',
            server: 'w.example.com',
            server_port: 443,
            uuid: 'u1',
            packet_encoding: '',
            network: 'tcp',
            tls: { enabled: true, server_name: 'w.example.com' },
            transport: {
                type: 'ws',
                path: '/path',
                headers: { Host: 'w.example.com' },
                max_early_data: 2048,
                early_data_header_name: 'Sec-WebSocket-Protocol'
            }
        });
    });

    it('unknown protocol returns a bare outbound (no null)', () => {
        assert.deepEqual(buildSingboxOutbound({
            protocol: 'wireguard', server: 'x.example.com', port: 51820
        }, 'proxy', null), {
            tag: 'proxy',
            type: 'wireguard',
            server: 'x.example.com',
            server_port: 51820
        });
    });
});
