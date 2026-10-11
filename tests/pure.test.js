const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const pure = require('../pure.js');

const {
    safeAtob, safeDecode, extractLines,
    getEchQueryServer, ECH_DNS_DEFAULT, isBareEchDomain, normalizeEchInput,
    ECH_PRESETS, FRAGMENT_PRESETS, SUB_SCHEME,
    subIsLink, subLooksLikeContent, subLooksLikeProxy, subValidate,
    parseProxyURLSingle, parseProxyURL, parseVless, parseVmess,
    parseTrojan, parseShadowsocks, parseSocks, parseHttp,
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
    });
});
