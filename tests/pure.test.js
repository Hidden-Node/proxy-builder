const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const pure = require('../pure.js');

const {
    safeAtob, safeDecode, extractLines,
    getEchQueryServer, ECH_DNS_DEFAULT, isBareEchDomain, normalizeEchInput,
    ECH_PRESETS, FRAGMENT_PRESETS, SUB_SCHEME,
    subIsLink, subLooksLikeContent, subLooksLikeProxy, subValidate
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
    it('locks the cf-udp default', () => {
        assert.equal(ECH_PRESETS['cf-udp'], 'cloudflare-ech.com+udp://1.1.1.1');
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
