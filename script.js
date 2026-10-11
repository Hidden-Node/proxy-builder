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
    const panelXray = document.getElementById('panel-xray');
    const panelSingbox = document.getElementById('panel-singbox');

    // Main tab elements
    const mainTabs = document.querySelectorAll('.main-tab');
    const viewChain = document.getElementById('view-chain');
    const viewEnhancer = document.getElementById('view-enhancer');
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
    // ECH per-tab state lives in its createEnhanceTab instance (026); globals removed.

    let parsedConfig1 = null;
    let parsedConfig2 = null;
    let sshMode1 = false;
    let sshMode2 = false;
    // lastAutoServer / lastAutoEchServer removed (026): per-instance closures
    // in the tab controllers.

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

    // ===== URL Enhancer (Fragment + Fingerprint) =====

    function enhanceURL(raw, opts) {
        return enhanceUrlCore(raw, {
            server: enhancerServer.value,
            fp: enhancerFp.value,
            cs: enhancerCs.value,
            fm: enhancerFm.value,
            ignoreServer: !!(opts && opts.ignoreServer)
        });
    }

    // Fragment URL-input/enhance originals removed (026): the fragTab
    // createEnhanceTab instance below owns this tab now (IDs, filenames,
    // option controls kept).

    // ===== ECH Enhancer (own tab — fp + ech only) =====

    function enhanceEchURL(raw, opts) {
        return enhanceEchUrlCore(raw, {
            server: echServer.value,
            fp: echFp.value,
            ech: echText.value,
            ignoreServer: !!(opts && opts.ignoreServer)
        });
    }

    // ECH URL-input/enhance originals removed (026): the echTab createEnhanceTab
    // instance below owns this tab now (IDs, filenames, option controls kept).

    // ===== ECH subscription input (link fetch or pasted contents, shared output) =====

    // setEchSubError removed (026): closure setTabSubError in the ECH tab controller.

    // Manual-fetch fallback for providers that block browser fetches (no CORS
    // headers): an "Open link" button + 3 steps, mirroring the Subscription tab.
    // Built with DOM APIs only (no innerHTML).
    // ECH CORS guide helper removed (026): closure in the tab controller.

    // syncEchOpenButton removed (026): closure syncTabOpenButton in the ECH tab controller.

    // ECH subscription originals removed (026): owned by the echTab instance.

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
                ? `<div class="error-msg">⚠️ ${escapeHtml(String(params.error))}</div>`
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
                    <span class="info-label">${escapeHtml(String(label))}</span>
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
                <span class="info-label">${escapeHtml(String(label))}</span>
                <span class="info-value">${escapeHtml(String(value))}</span>
            </div>`
        ).join('');
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
            btnCopyXray.disabled = true;
            btnDownloadXray.disabled = true;
            switchTab('singbox');
        } else {
            tabXray.classList.remove('disabled');
            tabXray.title = '';
            btnCopyXray.disabled = false;
            btnDownloadXray.disabled = false;
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
        // Defense in depth: block Xray output for SSH configs even if the
        // buttons are enabled. NOTE: the function-identity check breaks if a
        // later plan wraps generators — prefer an explicit isXray boolean
        // parameter then. Safe for now: plan 016 passes values, not wrappers.
        if (configGenerator === generateFullConfig && (parsedConfig1?.protocol === 'ssh' || parsedConfig2?.protocol === 'ssh')) return;
        const result = configGenerator(parsedConfig1, parsedConfig2);
        if (!result) return;

        const text = JSON.stringify(result.config, null, 2);
        copyTextWithFeedback(btn, text, generateHint);
    }

    function doDownload(configGenerator, prefix) {
        if (!parsedConfig1 || !parsedConfig2) return;
        // Defense in depth: block Xray output for SSH configs even if the
        // buttons are enabled. NOTE: the function-identity check breaks if a
        // later plan wraps generators — prefer an explicit isXray boolean
        // parameter then. Safe for now: plan 016 passes values, not wrappers.
        if (configGenerator === generateFullConfig && (parsedConfig1?.protocol === 'ssh' || parsedConfig2?.protocol === 'ssh')) return;
        const result = configGenerator(parsedConfig1, parsedConfig2);
        if (!result) return;

        const text = JSON.stringify(result.config, null, 2);
        downloadText(`${prefix}-${parsedConfig1.protocol}-${parsedConfig2.protocol}-${parsedConfig2.server}.json`, text, 'application/json');
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
    // SUB_IDLE_MS / SUB_TOTAL_MS live in pure.js (shared with subErrorText).

    // Fragment per-tab state lives in its createEnhanceTab instance (026); globals removed.

    // extractSubConfigs() lives in pure.js (shared global scope).

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
                if (total > SUB_MAX_FILE_BYTES) {
                    throw Object.assign(new Error('Subscription body exceeds 2 MiB'), { name: 'SubTooLarge' });
                }
                const keepAlive = setInterval(kick, Math.min(10000, SUB_IDLE_MS));
                try {
                    const text = await res.text();
                    if (new TextEncoder().encode(text).length > SUB_MAX_FILE_BYTES) {
                        throw Object.assign(new Error('Subscription body exceeds 2 MiB'), { name: 'SubTooLarge' });
                    }
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
                if (loaded > SUB_MAX_FILE_BYTES) {
                    try { await reader.cancel(); } catch (_) {}
                    throw Object.assign(new Error('Subscription body exceeds 2 MiB'), { name: 'SubTooLarge' });
                }
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

    // setSubError removed (026): closure setTabSubError in the fragTab controller.

    // Opens a subscription link for manual copying. The URL always comes from
    // the user's own paste (validated as a link before any call site runs),
    // so this is equivalent to them opening it from the address bar.
    function openSubLink(url) {
        window.open(url, '_blank', 'noopener');
    }

    // syncOpenButton removed (026): closure syncTabOpenButton in the fragTab controller.

    // setSubCorsGuide removed (026): closure setTabCorsGuide in the fragTab controller.

    // Accept a saved subscription file (.txt) dropped onto the card. Everything
    // stays local: FileReader never uploads anything.
    const SUB_MAX_FILE_BYTES = 2 * 1024 * 1024;
    // SUB_TOO_LARGE_MSG lives in pure.js (shared with subErrorText).

    // Fragment drop handlers removed (026): closures in the fragTab controller.

    // subIsBlockedError() / subErrorText() live in pure.js (shared global scope).

    // Verdicts that allow the Fetch button to run.
    function subCanRun(mode) {
        return mode === 'link' || mode === 'content';
    }

    // subShowInfo removed (026): closure showTabInfo in the fragTab controller.

    // onSubInput removed (026): closure onTabSubInput in the fragTab controller
    // (busy guard added, invalid card class added, subMode cache dropped).

    // renderSubResults removed (026): closure renderTabResults in the fragTab
    // controller (count rule unchanged — fragment's skipped++ was adopted).

    // scheduleSubRender / onSubStale / onSubFetched / onSubProgress removed (026):
    // closures scheduleTabRender / handleTabStale / onTabFetched / onTabProgress
    // in the fragTab controller (300 ms + 150 ms shapes kept).

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

    // Single copy-to-clipboard flow for the hinted tabs: async clipboard with a
    // guidance fallback where it doesn't exist (file:// / plain http), plus
    // the 2-second success morph.
    function copyTextWithFeedback(btn, text, hintEl) {
        if (!text) return;
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
            hintEl.textContent = 'Copy failed — select the output text and copy it manually';
            hintEl.style.color = '#f0c040';
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
            hintEl.textContent = 'Copy failed — select the output text and copy it manually';
            hintEl.style.color = '#f0c040';
        });
    }

    // ===== Unified enhance pipeline (Plan 026) =====
    // Single fetch→extract→render→export flow parameterized by enhance fn + option
    // handles. Parity policies (locked): countRule fragment's skipped++ on both;
    // busy guard (ECH freeze-button) on both; URL-input hides shared output (ECH)
    // on both; remark host post-override re-read (ECH) on both; empty-enhance red
    // hint (ECH wording) on both; failureCopy.noConfigs ECH wording on both;
    // CORS step-3 + export filenames stay per-tab; 012 SSH guards + 018 helper
    // routing + 019 b64 helper calls + 023 debounced schedulers preserved.
    // Extra accepted fixes (see NOTES): fetch-start clears url/remark text (ECH) on
    // both; drop-error re-validates (ECH) on both; input-invalid adds invalid card
    // class (ECH) on both; fetch-completion clears queued render timer (fragment)
    // on both; sub paste setTimeout(…,50) (ECH) as superset for both.
    // pure.js is FROZEN — this consumes stable enhanceUrlCore/enhanceEchUrlCore
    // signatures via enhanceSingle/enhanceBulk, never rewrites them.
    function createEnhanceTab(cfg) {
        const {
            enhanceSingle, enhanceBulk,
            ids, urlJoin, subJoin, remarkJoiner,
            corsGuideStep3, exportNames, failureCopy,
            countRule, showProtocolTag, busyGuardOnInput,
            optionWatch, subCopy, copyHintEl, serverEl
        } = cfg;
        const {
            urlInput, urlClear, urlParsed, urlProtocolTag, urlCard, btnUrlEnhance, urlHint,
            subCard, subInput, subClear, subParsed, subProtocolTag,
            btnSub, btnOpenSub, subHint,
            outputSection, outputUrl, outputRemark,
            btnCopy, btnDownload, btnDownloadB64
        } = ids;
        const bulkEnhance = enhanceBulk || ((line) => enhanceSingle(line, { ignoreServer: true }));
        const URL_JOIN = urlJoin || '\n\n';
        const SUB_JOIN = subJoin || '\n';
        const REMARK_JOINER = remarkJoiner || ' · ';
        let outputList = [];
        let subRaw = [];
        let lastSource = '';
        let busy = false;
        let progressTimer = null;
        let renderTimer = null;
        let lastAutoServerLocal = '';
        let urlInputTimer = null;

        function setTabSubError(text) {
            subParsed.textContent = '';
            const err = document.createElement('div');
            err.className = 'error-msg';
            err.textContent = '⚠️ ' + text;
            subParsed.appendChild(err);
        }

        function showTabInfo(label, value) {
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

        function syncTabOpenButton() {
            btnOpenSub.disabled = subValidate(subInput.value.trim()) !== 'link';
        }

        function onTabUrlInput() {
            // URL edit invalidates shared output (ECH behavior) on BOTH tabs.
            subRaw = [];
            lastSource = '';
            outputList = [];
            outputSection.style.display = 'none';
            outputUrl.textContent = '';
            outputRemark.textContent = '';
            const val = urlInput.value.trim();
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
            if (parsedList.length === 1) {
                const firstServer = parsedList[0].server || '';
                const current = serverEl.value.trim();
                if (!current || current === lastAutoServerLocal || current === firstServer) {
                    serverEl.value = firstServer;
                    lastAutoServerLocal = firstServer;
                }
            } else if (parsedList.length > 1) {
                const current = serverEl.value.trim();
                if (!current || current === lastAutoServerLocal) {
                    serverEl.value = '';
                    lastAutoServerLocal = '';
                }
            } else if (!serverEl.value.trim()) {
                lastAutoServerLocal = '';
            }
            if (lines.length > 0) {
                if (parsedList.length > 0) {
                    renderParsedInfo(parsedList.length === 1 ? parsedList[0] : parsedList, urlParsed);
                    const protocols = Array.from(new Set(parsedList.map(p => p.protocol)));
                    if (protocols.length === 1) {
                        updateProtocolTag(urlProtocolTag, parsedList[0]);
                    } else {
                        urlProtocolTag.textContent = 'MULTI';
                        urlProtocolTag.classList.add('active');
                        urlProtocolTag.style.color = '#7c5cff';
                        urlProtocolTag.style.borderColor = '#7c5cff4d';
                        urlProtocolTag.style.background = '#7c5cff1a';
                    }
                } else {
                    renderParsedInfo({
                        error: unsupportedCount > 0
                            ? 'Only VLESS and Trojan URLs are supported'
                            : 'Failed to parse URL'
                    }, urlParsed);
                    updateProtocolTag(urlProtocolTag, null);
                }
            } else {
                renderParsedInfo(null, urlParsed);
                updateProtocolTag(urlProtocolTag, null);
            }
            urlCard.classList.remove('valid', 'invalid');
            if (lines.length > 0 && parsedList.length > 0) {
                urlCard.classList.add('valid');
            } else if (lines.length > 0) {
                urlCard.classList.add('invalid');
            }
            const count = parsedList.length;
            btnUrlEnhance.disabled = count === 0;
            btnUrlEnhance.innerHTML = `<span class="btn-icon">✨</span> Enhance ${count > 1 ? count + ' URLs' : 'URL'}`;
            urlHint.textContent = count > 0
                ? `Ready to enhance ${count} URL${count > 1 ? 's' : ''}!`
                : 'Paste VLESS or Trojan URL(s) above to enable';
            urlHint.style.color = count > 0 ? '#4cdf86' : '';
        }

        function onTabUrlEnhance() {
            const val = urlInput.value.trim();
            const lines = extractLines(val);
            if (lines.length === 0) {
                outputSection.style.display = 'none';
                return;
            }
            const enhancedUrls = [];
            let firstEnhanced = null;
            lines.forEach(line => {
                const p = parseProxyURLSingle(line);
                if (p && !p.error && (p.protocol === 'vless' || p.protocol === 'trojan')) {
                    const res = enhanceSingle(line);
                    if (res && res.url) {
                        if (!firstEnhanced) firstEnhanced = p;
                        enhancedUrls.push(res.url);
                    }
                }
            });
            if (enhancedUrls.length === 0) {
                outputSection.style.display = 'none';
                outputList = [];
                urlHint.textContent = 'Could not enhance — check the URLs and the Server override';
                urlHint.style.color = '#f05050';
                return;
            }
            const count = enhancedUrls.length;
            const firstParsed = firstEnhanced;
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
            outputList = enhancedUrls;
            outputRemark.textContent = remark;
            outputUrl.textContent = enhancedUrls.join(URL_JOIN);
            outputSection.style.display = 'block';
            lastSource = 'url';
            outputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        function scheduleTabUrlInput() {
            if (!urlInput.value.trim()) {
                clearTimeout(urlInputTimer);
                urlInputTimer = null;
                onTabUrlInput();
                return;
            }
            clearTimeout(urlInputTimer);
            urlInputTimer = setTimeout(() => {
                urlInputTimer = null;
                onTabUrlInput();
            }, 150);
        }

        function onTabSubInput() {
            const raw = subInput.value.trim();
            if (busyGuardOnInput && busy) {
                btnSub.disabled = true;
                return;
            }
            subCard.classList.remove('valid', 'invalid');
            if (showProtocolTag && subProtocolTag) {
                subProtocolTag.classList.remove('active');
                subProtocolTag.textContent = '—';
            }
            subRaw = [];
            outputSection.style.display = 'none';
            outputUrl.textContent = '';
            outputRemark.textContent = '';
            outputList = [];
            subParsed.textContent = '';
            subHint.style.color = '';
            btnOpenSub.disabled = true;
            if (!raw) {
                btnSub.disabled = true;
                btnOpenSub.disabled = true;
                subHint.textContent = subCopy.empty;
                return;
            }
            const mode = subValidate(raw);
            if (mode === 'link') {
                subCard.classList.add('valid');
                if (showProtocolTag && subProtocolTag) {
                    const u = new URL(raw);
                    subProtocolTag.textContent = u.protocol.replace(':', '').toUpperCase() || 'HTTP';
                    subProtocolTag.classList.add('active');
                    showTabInfo('Host', u.hostname);
                }
                btnSub.disabled = false;
                syncTabOpenButton();
                subHint.textContent = subCopy.linkReady;
                subHint.style.color = '#4cdf86';
                return;
            }
            if (mode === 'content') {
                subCard.classList.add('valid');
                if (showProtocolTag && subProtocolTag) {
                    subProtocolTag.textContent = 'CONTENT';
                    subProtocolTag.classList.add('active');
                    showTabInfo('Mode', 'Pasted content — nothing will be fetched');
                }
                btnSub.disabled = false;
                syncTabOpenButton();
                subHint.textContent = subCopy.contentReady;
                subHint.style.color = '#4cdf86';
                return;
            }
            if (mode === 'proxy') {
                subCard.classList.add('invalid');
                setTabSubError(subCopy.proxyError);
                btnSub.disabled = true;
                btnOpenSub.disabled = true;
                subHint.textContent = subCopy.proxyHint;
                return;
            }
            subCard.classList.add('invalid');
            if (subCopy.invalidError) setTabSubError(subCopy.invalidError);
            btnSub.disabled = true;
            btnOpenSub.disabled = true;
            subHint.textContent = subCopy.invalidHint;
        }

        function renderTabResults(configs, focus) {
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
                const res = bulkEnhance(line);
                if (res && res.url) {
                    enhanced.push(res.url);
                } else {
                    // countRule fragment's skipped++ (never relabels
                    // parsed-but-unenhanceable as unparseable); ECH's
                    // invalid-if-scheme branch is deleted.
                    skipped++;
                }
            });
            if (enhanced.length === 0) {
                outputSection.style.display = 'none';
                outputList = [];
                subHint.textContent = configs.length
                    ? 'Found configs, but none were VLESS/Trojan with a usable URL'
                    : 'No proxy configs found in the input';
                subHint.style.color = '#f0c040';
                subCard.classList.remove('valid');
                subCard.classList.add('invalid');
                setTabSubError(configs.length
                    ? configs.length + ' config(s) found, but none could be enhanced — only VLESS and Trojan URLs are supported.'
                    : failureCopy.noConfigs);
                return;
            }
            outputList = enhanced;
            subParsed.textContent = '';
            subCard.classList.remove('invalid');
            subCard.classList.add('valid');
            const parts = ['✨ ' + enhanced.length + ' enhanced config(s)'];
            if (skipped) parts.push('skipped ' + skipped + ' non-VLESS/Trojan');
            if (invalid) parts.push('ignored ' + invalid + ' unparseable line(s)');
            outputRemark.textContent = parts.join(REMARK_JOINER);
            outputUrl.textContent = enhanced.join(SUB_JOIN);
            outputSection.style.display = 'block';
            lastSource = 'sub';
            if (focus) outputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
            subHint.textContent = 'Done';
            subHint.style.color = '#4cdf86';
        }

        function scheduleTabRender() {
            if (busy || !subRaw.length || lastSource !== 'sub') return;
            clearTimeout(renderTimer);
            renderTimer = setTimeout(() => {
                renderTimer = null;
                if (busy || !subRaw.length || lastSource !== 'sub') return;
                renderTabResults(subRaw, false);
            }, 300);
        }

        function handleTabStale() {
            subRaw = [];
            onTabSubInput();
            subHint.textContent = 'Input changed during the fetch — fetch again';
            subHint.style.color = '#f0c040';
        }

        function onTabFetched(body, fetchRaw) {
            if (!busy) return;
            busy = false;
            if (progressTimer) {
                clearTimeout(progressTimer);
                progressTimer = null;
            }
            if (renderTimer) {
                clearTimeout(renderTimer);
                renderTimer = null;
            }
            if (subInput.value.trim() !== fetchRaw) {
                handleTabStale();
                return;
            }
            btnSub.disabled = false;
            syncTabOpenButton();
            const configs = extractSubConfigs(body);
            subRaw = configs;
            renderTabResults(configs, true);
        }

        function onTabProgress(loaded, total) {
            if (progressTimer) return;
            progressTimer = setTimeout(() => {
                progressTimer = null;
                if (!busy) return;
                const kb = Math.round(loaded / 1024);
                subHint.textContent = total
                    ? 'Fetching… ' + kb + ' / ' + Math.round(total / 1024) + ' KB'
                    : 'Fetching… ' + kb + ' KB';
            }, 150);
        }

        async function onTabSub() {
            const raw = subInput.value.trim();
            if (!raw || busy) return;
            const mode = subValidate(raw);
            if (!subCanRun(mode)) {
                onTabSubInput();
                return;
            }
            if (mode === 'content') {
                subRaw = extractSubConfigs(raw);
                renderTabResults(subRaw, true);
                return;
            }
            busy = true;
            btnSub.disabled = true;
            btnOpenSub.disabled = true;
            subHint.textContent = 'Fetching…';
            subHint.style.color = '';
            subParsed.textContent = '';
            subCard.classList.remove('invalid');
            outputSection.style.display = 'none';
            outputUrl.textContent = '';
            outputRemark.textContent = '';
            outputList = [];
            subRaw = [];
            try {
                const body = await fetchSubBody(raw, onTabProgress);
                onTabFetched(body, raw);
            } catch (e) {
                busy = false;
                if (progressTimer) {
                    clearTimeout(progressTimer);
                    progressTimer = null;
                }
                if (subInput.value.trim() !== raw) {
                    handleTabStale();
                    return;
                }
                btnSub.disabled = false;
                syncTabOpenButton();
                subHint.textContent = 'Fetch failed';
                subHint.style.color = '#f05050';
                subCard.classList.remove('valid');
                subCard.classList.add('invalid');
                setTabSubError(subErrorText(e));
                syncTabOpenButton();
                if (subIsBlockedError(e) && (typeof navigator === 'undefined' || navigator.onLine !== false)) setTabCorsGuide(raw);
            }
        }

        function setTabCorsGuide(linkUrl) {
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
            third.textContent = corsGuideStep3;
            steps.append(first, second, third);
            guide.append(title, steps);
            subParsed.appendChild(guide);
        }

        function onTabDropError(text) {
            outputSection.style.display = 'none';
            outputUrl.textContent = '';
            outputRemark.textContent = '';
            outputList = [];
            subRaw = [];
            onTabSubInput();
            setTabSubError(text);
            outputList = [];
        }

        function onTabDragOver(e) {
            e.preventDefault();
            subCard.classList.add('dragover');
        }

        function onTabDragLeave(e) {
            e.preventDefault();
            if (e.relatedTarget && subCard.contains(e.relatedTarget)) return;
            subCard.classList.remove('dragover');
        }

        function onTabDrop(e) {
            e.preventDefault();
            subCard.classList.remove('dragover');
            const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
            if (!file) return;
            if (file.size > SUB_MAX_FILE_BYTES) {
                onTabDropError(SUB_TOO_LARGE_MSG);
                return;
            }
            const reader = new FileReader();
            reader.onload = () => {
                subInput.value = String(reader.result || '');
                onTabSubInput();
                subInput.focus();
            };
            reader.onerror = () => onTabDropError('Could not read that file.');
            reader.readAsText(file);
        }

        function onTabUrlDragOver(e) {
            e.preventDefault();
            urlCard.classList.add('dragover');
        }

        function onTabUrlDragLeave(e) {
            e.preventDefault();
            if (e.relatedTarget && urlCard.contains(e.relatedTarget)) return;
            urlCard.classList.remove('dragover');
        }

        function onTabUrlDrop(e) {
            dropTextFileOnto(e, urlCard, urlInput, onTabUrlInput, urlHint);
        }

        function wireTab() {
            urlInput.addEventListener('input', scheduleTabUrlInput);
            urlInput.addEventListener('paste', scheduleTabUrlInput);
            if (urlClear) urlClear.addEventListener('click', () => {
                urlInput.value = '';
                onTabUrlInput();
            });
            urlCard.addEventListener('dragenter', onTabUrlDragOver);
            urlCard.addEventListener('dragover', onTabUrlDragOver);
            urlCard.addEventListener('dragleave', onTabUrlDragLeave);
            urlCard.addEventListener('drop', onTabUrlDrop);
            btnUrlEnhance.addEventListener('click', onTabUrlEnhance);
            if (btnCopy) btnCopy.addEventListener('click', () => copyTextWithFeedback(btnCopy, outputUrl.textContent, copyHintEl || subHint));
            subInput.addEventListener('input', onTabSubInput);
            subInput.addEventListener('paste', () => setTimeout(onTabSubInput, 50));
            if (subClear) subClear.addEventListener('click', () => {
                subInput.value = '';
                onTabSubInput();
            });
            btnSub.addEventListener('click', onTabSub);
            btnOpenSub.addEventListener('click', () => {
                const v = subInput.value.trim();
                if (subValidate(v) === 'link') openSubLink(v);
            });
            subCard.addEventListener('dragenter', onTabDragOver);
            subCard.addEventListener('dragover', onTabDragOver);
            subCard.addEventListener('dragleave', onTabDragLeave);
            subCard.addEventListener('drop', onTabDrop);
            (optionWatch || []).forEach(pair => {
                const el = pair.el || pair[0];
                const ev = pair.event || pair[1];
                if (el && ev) el.addEventListener(ev, scheduleTabRender);
            });
            if (btnDownload) btnDownload.addEventListener('click', () => {
                if (!outputList.length) return;
                downloadText(exportNames.txt, outputUrl.textContent + '\n');
            });
            if (btnDownloadB64) btnDownloadB64.addEventListener('click', () => {
                if (!outputList.length) return;
                downloadText(exportNames.b64, encodeUtf8ToB64(outputUrl.textContent));
            });
        }

        return {
            onTabUrlInput, onTabUrlEnhance, scheduleTabUrlInput,
            onTabSubInput, renderTabResults, scheduleTabRender,
            onTabSub, onTabFetched, handleTabStale, onTabProgress,
            setTabCorsGuide, syncTabOpenButton, wireTab,
            getState: () => ({ outputList, subRaw, lastSource, busy })
        };
    }

    // ECH tab instance (026): parity policies applied (skipped++ count, busy guard,
    // hide-on-edit, post-override remark, red-hint failure, ECH noConfigs wording).
    // IDs, filenames, option controls preserved; 019 helper calls + 023 scheduler
    // shapes preserved via the controller.
    const echTab = createEnhanceTab({
        enhanceSingle: enhanceEchURL,
        ids: {
            urlInput: echInput, urlClear: echClear, urlParsed: echParsed,
            urlProtocolTag: echProtocolTag, urlCard: echCard,
            btnUrlEnhance: btnEchEnhance, urlHint: echHint,
            subCard: echSubCard, subInput: echSubInput, subClear: echSubClear,
            subParsed: echSubParsed, subProtocolTag: null,
            btnSub: btnEchSub, btnOpenSub: btnEchOpenSub, subHint: echSubHint,
            outputSection: echOutputSection, outputUrl: echOutputUrl,
            outputRemark: echOutputRemark,
            btnCopy: btnCopyEch, btnDownload: btnDownloadEch, btnDownloadB64: btnDownloadEchB64
        },
        serverEl: echServer,
        urlJoin: '\n\n',
        subJoin: '\n',
        remarkJoiner: ' · ',
        corsGuideStep3: 'Paste it into the subscription box above and press Fetch & Enhance Sub.',
        exportNames: { txt: 'ech-enhanced-configs.txt', b64: 'ech-enhanced-configs-base64.txt' },
        failureCopy: { noConfigs: 'No recognizable VLESS/Trojan configs in the input. Open the link in a new tab and paste its contents here.' },
        countRule: 'skipped',
        showProtocolTag: false,
        busyGuardOnInput: true,
        optionWatch: [
            { el: echFp, event: 'change' },
            { el: echPreset, event: 'change' },
            { el: echText, event: 'input' }
        ],
        subCopy: {
            empty: 'Paste a subscription link — or its contents — above to enable',
            linkReady: 'Ready to fetch & enhance',
            contentReady: 'Ready to enhance pasted contents',
            proxyHint: 'That looks like an HTTP proxy address, not a subscription',
            proxyError: 'That looks like an HTTP proxy address, not a subscription link. Only VLESS and Trojan URLs can be enhanced — paste one of those, or a subscription link. If this is actually a subscription served at a bare address with no path, open it in a new tab and paste its contents here instead.',
            invalidHint: 'Unrecognized input — paste a subscription link or its contents',
            invalidError: null
        },
        copyHintEl: echHint
    });
    echTab.wireTab();

    // Fragment tab instance (026): same controller, fragment option set +
    // per-tab data (filenames, CORS step-3, subCopy verbatim). Five intended
    // behavior changes vs the deleted originals: busy guard on sub-input,
    // URL-input hides shared output, post-override remark re-read, red-hint
    // empty-enhance failure, ECH noConfigs wording. 019 helper calls + 023
    // scheduler shapes preserved via the controller.
    const fragTab = createEnhanceTab({
        enhanceSingle: enhanceURL,
        ids: {
            urlInput: enhancerInput, urlClear: enhancerClear, urlParsed: enhancerParsed,
            urlProtocolTag: enhancerProtocolTag, urlCard: enhancerCard,
            btnUrlEnhance: btnEnhance, urlHint: enhanceHint,
            subCard: subCard, subInput: subUrl, subClear: subClear,
            subParsed: subParsed, subProtocolTag: subProtocolTag,
            btnSub: btnSub, btnOpenSub: btnOpenSub, subHint: subHint,
            outputSection: subOutputSection, outputUrl: subOutputUrl,
            outputRemark: subOutputRemark,
            btnCopy: btnCopySub, btnDownload: btnDownloadSub, btnDownloadB64: btnDownloadSubB64
        },
        serverEl: enhancerServer,
        urlJoin: '\n\n',
        subJoin: '\n',
        remarkJoiner: ' · ',
        corsGuideStep3: 'Paste it into the box above and press Fetch & Enhance.',
        exportNames: { txt: 'enhanced-configs.txt', b64: 'enhanced-configs-base64.txt' },
        failureCopy: { noConfigs: 'No recognizable VLESS/Trojan configs in the input. Open the link in a new tab and paste its contents here.' },
        countRule: 'skipped',
        showProtocolTag: true,
        busyGuardOnInput: true,
        optionWatch: [
            { el: enhancerFp, event: 'change' },
            { el: enhancerFmPreset, event: 'change' },
            { el: enhancerCs, event: 'input' },
            { el: enhancerFm, event: 'input' }
        ],
        subCopy: {
            empty: 'Paste a subscription link — or its contents — to enable',
            linkReady: 'Ready to fetch and enhance',
            contentReady: 'Ready to enhance pasted content',
            proxyHint: 'Paste a subscription link or a VLESS/Trojan URL',
            proxyError: 'That looks like an HTTP proxy address, not a subscription link. Only VLESS and Trojan URLs can be enhanced — paste one of those, or a subscription link. If this is actually a subscription served at a bare address with no path, open it in a new tab and paste its contents here instead.',
            invalidHint: 'Paste a valid link above to enable',
            invalidError: 'Invalid input. Paste a link starting with http:// or https://, or paste the subscription contents.'
        },
        copyHintEl: subHint
    });
    fragTab.wireTab();

    // Fragment sub-input/fetch/copy/download wiring removed (026): owned by the
    // fragTab instance (filenames + watched controls unchanged).

    // ===== Main Tab switching =====
    function switchMainTab(viewName) {
        mainTabs.forEach(t => {
            t.classList.toggle('active', t.dataset.view === viewName);
        });
        viewChain.style.display = viewName === 'chain' ? '' : 'none';
        viewEnhancer.style.display = viewName === 'enhancer' ? '' : 'none';
        viewEch.style.display = viewName === 'ech' ? '' : 'none';
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
    // Debounced chain-config inputs (150 ms keeps typing snappy): every
    // keystroke re-parses and rebuilds the parsed-info panel, so the timer
    // coalesces bursts from large pastes — same shape as scheduleSubRender
    // (which uses 300 ms for option changes). An emptied field runs
    // synchronously so button-disable feedback never lags a clear and
    // parsedConfig1/2 can't go stale if Generate is clicked mid-delay.
    // Paste shares this scheduler: paste fires both paste and input, and one
    // timer means one parse instead of two.
    let config1InputTimer = null;
    function scheduleConfig1Input() {
        if (!config1Input.value.trim()) {
            clearTimeout(config1InputTimer);
            config1InputTimer = null;
            onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true);
            return;
        }
        clearTimeout(config1InputTimer);
        config1InputTimer = setTimeout(() => {
            config1InputTimer = null;
            onInputChange(config1Input, parsed1, protocol1Tag, config1Card, true);
        }, 150);
    }
    let config2InputTimer = null;
    function scheduleConfig2Input() {
        if (!config2Input.value.trim()) {
            clearTimeout(config2InputTimer);
            config2InputTimer = null;
            onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false);
            return;
        }
        clearTimeout(config2InputTimer);
        config2InputTimer = setTimeout(() => {
            config2InputTimer = null;
            onInputChange(config2Input, parsed2, protocol2Tag, config2Card, false);
        }, 150);
    }
    config1Input.addEventListener('input', scheduleConfig1Input);
    config2Input.addEventListener('input', scheduleConfig2Input);
    config1Input.addEventListener('paste', scheduleConfig1Input);
    config2Input.addEventListener('paste', scheduleConfig2Input);

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
    if (enhancerFmPreset) {
        enhancerFmPreset.addEventListener('change', () => {
            const preset = FRAGMENT_PRESETS[enhancerFmPreset.value];
            if (preset !== undefined) {
                enhancerFm.value = preset;
            }
        });
    }
    if (echPreset) {
        echPreset.addEventListener('change', () => {
            echText.value = ECH_PRESETS[echPreset.value] || '';
        });
    }
    // ===== Shared .txt drop onto URL cards =====
    // One helper for both URL cards: dropped text must equal pasted text, so
    // there is no parsing here — it only sets the textarea value and calls
    // the card's existing input handler (button/hint/parsed update through
    // the normal path). Everything stays local: file.text() never uploads.
    function dropTextFileOnto(e, card, textarea, onInput, hint) {
        e.preventDefault();
        card.classList.remove('dragover');
        const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
        if (!file) return;
        if (file.size > SUB_MAX_FILE_BYTES) {
            hint.textContent = 'That file is too large — drop a plain-text URL list (.txt), usually a few hundred KB at most.';
            hint.style.color = '#f05050';
            return;
        }
        if (!/\.txt$/i.test(file.name || '')) {
            hint.textContent = 'Only .txt files can be dropped here — paste the URLs instead.';
            hint.style.color = '#f05050';
            return;
        }
        file.text().then(text => {
            textarea.value = text;
            onInput();
            textarea.focus();
        }).catch(() => {
            hint.textContent = 'Could not read that file.';
            hint.style.color = '#f05050';
        });
    }
    // Fragment URL-card drag handlers removed (026): owned by the fragTab instance.
    // ECH URL-card drag + debounced input + enhance/copy wiring removed (026):
    // owned by the echTab instance (same dropTextFileOnto helper, 150 ms shape).
    // Fragment URL-input debounce + card/enhance wiring removed (026): owned by
    // the fragTab instance (same dropTextFileOnto helper, 150 ms shape).
    // ECH sub-input/sub-button wiring removed (026): owned by the echTab instance.
    // ECH input-mode sub-tabs (scoped to #view-ech so the sing-box panels
    // driven by the generic switchSubTab are untouched).
    const echSubTabs = Array.from(document.querySelectorAll('#view-ech .sub-tab'));
    const echSubPanels = {
        url: document.getElementById('ech-subpanel-url'),
        sub: document.getElementById('ech-subpanel-sub')
    };
    // Generate buttons live below the shared options card (like the
    // Fragment + Fingerprint tab), so they toggle with the panels.
    const echGenerateSections = {
        url: document.getElementById('ech-generate-url'),
        sub: document.getElementById('ech-generate-sub')
    };
    function switchEchSubTab(name) {
        echSubTabs.forEach(t => t.classList.toggle('active', t.dataset.echsubtab === name));
        Object.entries(echSubPanels).forEach(([key, panel]) => {
            if (panel) panel.classList.toggle('active', key === name);
        });
        Object.entries(echGenerateSections).forEach(([key, section]) => {
            if (section) section.classList.toggle('active', key === name);
        });
    }
    echSubTabs.forEach(tab => {
        tab.addEventListener('click', () => switchEchSubTab(tab.dataset.echsubtab));
    });
    // Fragment + Fingerprint input-mode sub-tabs (same pattern as ECH:
    // scoped to #view-enhancer so the sing-box panels driven by the
    // generic switchSubTab are untouched).
    const enhancerSubTabs = Array.from(document.querySelectorAll('#view-enhancer .sub-tab'));
    const enhancerSubPanels = {
        url: document.getElementById('enhancer-subpanel-url'),
        sub: document.getElementById('enhancer-subpanel-sub')
    };
    // Generate buttons live below the shared options card, so they toggle
    // with the panels.
    const enhancerGenerateSections = {
        url: document.getElementById('enhancer-generate-url'),
        sub: document.getElementById('enhancer-generate-sub')
    };
    function switchEnhancerSubTab(name) {
        enhancerSubTabs.forEach(t => t.classList.toggle('active', t.dataset.enhsubtab === name));
        Object.entries(enhancerSubPanels).forEach(([key, panel]) => {
            if (panel) panel.classList.toggle('active', key === name);
        });
        Object.entries(enhancerGenerateSections).forEach(([key, section]) => {
            if (section) section.classList.toggle('active', key === name);
        });
    }
    enhancerSubTabs.forEach(tab => {
        tab.addEventListener('click', () => switchEnhancerSubTab(tab.dataset.enhsubtab));
    });
    // Downloads export exactly what is displayed, so Copy and both files
    // always agree (URL mode shows blank-line separation, sub mode single).
    // ECH downloads / sub-card drag / option-watch wiring removed (026): owned
    // by the echTab instance (filenames + watched controls unchanged).
})();
