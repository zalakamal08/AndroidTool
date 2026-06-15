"""Frida Worker — Dynamic instrumentation via Frida."""
import os
import subprocess
import tempfile
import time
import lzma
import urllib.request
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal


# ── Built-in Frida scripts ────────────────────────────────────────────────────

SCRIPTS: dict[str, str] = {

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP TOOLKIT LEVEL — Full SSL/TLS bypass (based on official HTK scripts)
    # Source: https://github.com/httptoolkit/frida-interception-and-unpinning
    # Trust-all mode (no CA cert required) for mobile pentesting.
    # Layers: 25+ Java pinning libs · Conscrypt injection · fallback patcher
    #         · native BoringSSL/Cronet hooks · WebView · X509TrustManagerExtensions
    # ─────────────────────────────────────────────────────────────────────────
    "httptoolkit_level": r"""
// ═══════════════════════════════════════════════════════════════════════════
// HTTP Toolkit Level — Comprehensive SSL/TLS Bypass for Android
// Based on: https://github.com/httptoolkit/frida-interception-and-unpinning
// Trust-all mode (no CA cert required) for mobile pentesting
// ═══════════════════════════════════════════════════════════════════════════

const DEBUG_MODE = false;

// ── Module-loading utility (mirrors config.js waitForModule) ─────────────
const _HTK_MODULE_CALLBACKS = {};
const _htk_getName = (p) => { const i = p.lastIndexOf('/'); return p.slice(i + 1); };

function waitForModule(moduleName, callback) {
    if (Array.isArray(moduleName)) { moduleName.forEach(m => waitForModule(m, callback)); return; }
    try { callback(Process.getModuleByName(moduleName)); return; } catch (e) {}
    try { callback(Module.load(moduleName)); return; } catch (e) {}
    _HTK_MODULE_CALLBACKS[moduleName] = callback;
}

// Hook dlopen so we catch dynamically-loaded native libs
try {
    new ApiResolver('module').enumerateMatches('exports:linker*!*dlopen*').forEach((dlopen) => {
        Interceptor.attach(dlopen.address, {
            onEnter(args) {
                try { this.modName = _htk_getName(args[0].readCString() ?? ''); } catch (e) {}
            },
            onLeave(retval) {
                if (!this.modName || !retval || retval.isNull()) return;
                const cb = _HTK_MODULE_CALLBACKS[this.modName];
                if (!cb) return;
                const mod = Process.findModuleByName(this.modName) ?? Process.findModuleByAddress(retval);
                if (mod) { cb(mod); delete _HTK_MODULE_CALLBACKS[this.modName]; }
            }
        });
    });
} catch (e) { if (DEBUG_MODE) console.log('[SSL] dlopen hook failed: ' + e); }

// ── Universal TrustManager (trust everything) ─────────────────────────────
function _getUniversalTrustManagers() {
    try {
        let UTM;
        try { UTM = Java.use('com.htk.bypass.UniversalTM'); }
        catch (e) {
            UTM = Java.registerClass({
                name: 'com.htk.bypass.UniversalTM',
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
        }
        return Java.array('javax.net.ssl.TrustManager', [UTM.$new()]);
    } catch (e) { console.error('[SSL] UniversalTrustManager error: ' + e); return null; }
}

const NO_OP     = () => {};
const RETURN_TRUE = () => true;
const _cls = (n) => { try { return Java.use(n); } catch { return undefined; } };

// ── Comprehensive pinning-fix table (HTTP Toolkit android-certificate-unpinning.js + extras) ──
const PINNING_FIXES = {
    'javax.net.ssl.HttpsURLConnection': [
        { methodName: 'setDefaultHostnameVerifier', replacement: () => NO_OP },
        { methodName: 'setSSLSocketFactory',        replacement: () => NO_OP },
        { methodName: 'setHostnameVerifier',         replacement: () => NO_OP },
    ],
    'javax.net.ssl.SSLContext': [
        {
            methodName: 'init',
            overload: ['[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'],
            replacement: (m) => function (km, _tm, sr) {
                const tms = _getUniversalTrustManagers();
                return m.call(this, km, tms, sr);
            }
        }
    ],
    'com.android.org.conscrypt.CertPinManager': [
        { methodName: 'isChainValid',      replacement: () => RETURN_TRUE },
        { methodName: 'checkChainPinning', replacement: () => NO_OP }
    ],
    'com.android.org.conscrypt.TrustManagerImpl': [
        {
            methodName: 'checkServerTrusted',
            overload: '*',
            replacement: (m) => m.returnType.className === 'java.util.List'
                ? (certs) => Java.use('java.util.Arrays').asList(certs)
                : () => {}
        },
        { methodName: 'verifyChain',           overload: '*', replacement: () => function (chain) { return chain; } },
        { methodName: 'checkTrustedRecursive', overload: '*', replacement: () => function () { return Java.use('java.util.ArrayList').$new(); } }
    ],
    'org.conscrypt.TrustManagerImpl': [
        {
            methodName: 'checkServerTrusted',
            overload: '*',
            replacement: (m) => m.returnType.className === 'java.util.List'
                ? (certs) => Java.use('java.util.Arrays').asList(certs)
                : () => {}
        },
        { methodName: 'verifyChain',           overload: '*', replacement: () => function (chain) { return chain; } },
        { methodName: 'checkTrustedRecursive', overload: '*', replacement: () => function () { return Java.use('java.util.ArrayList').$new(); } }
    ],
    'com.google.android.gms.org.conscrypt.TrustManagerImpl': [
        {
            methodName: 'checkServerTrusted',
            overload: '*',
            replacement: (m) => m.returnType.className === 'java.util.List'
                ? (certs) => Java.use('java.util.Arrays').asList(certs)
                : () => {}
        },
        { methodName: 'verifyChain',           overload: '*', replacement: () => function (chain) { return chain; } },
        { methodName: 'checkTrustedRecursive', overload: '*', replacement: () => function () { return Java.use('java.util.ArrayList').$new(); } }
    ],
    'com.android.org.conscrypt.ct.CertificateTransparency':              [{ methodName: 'checkCT', replacement: () => NO_OP }],
    'org.conscrypt.ct.CertificateTransparency':                          [{ methodName: 'checkCT', replacement: () => NO_OP }],
    'com.google.android.gms.org.conscrypt.ct.CertificateTransparency':  [{ methodName: 'checkCT', replacement: () => NO_OP }],
    'android.security.net.config.NetworkSecurityConfig': [
        {
            methodName: '$init',
            overload: '*',
            replacement: (m) => {
                const EMPTY = Java.use('android.security.net.config.PinSet').EMPTY_PINSET.value;
                return function () { arguments[2] = EMPTY; m.call(this, ...arguments); };
            }
        }
    ],
    'android.security.net.config.NetworkSecurityTrustManager': [
        { methodName: 'checkPins', replacement: () => NO_OP }
    ],
    'com.android.okhttp.internal.tls.OkHostnameVerifier': [
        {
            methodName: 'verify',
            overload: ['java.lang.String', 'javax.net.ssl.SSLSession'],
            replacement: () => RETURN_TRUE
        }
    ],
    'com.android.okhttp.Address': [
        {
            methodName: '$init',
            overload: ['java.lang.String','int','com.android.okhttp.Dns','javax.net.SocketFactory','javax.net.ssl.SSLSocketFactory','javax.net.ssl.HostnameVerifier','com.android.okhttp.CertificatePinner','com.android.okhttp.Authenticator','java.net.Proxy','java.util.List','java.util.List','java.net.ProxySelector'],
            replacement: (m) => {
                const hv = Java.use('com.android.okhttp.internal.tls.OkHostnameVerifier').INSTANCE.value;
                const cp = Java.use('com.android.okhttp.CertificatePinner').DEFAULT.value;
                return function () { arguments[5] = hv; arguments[6] = cp; m.call(this, ...arguments); };
            }
        },
        {
            methodName: '$init',
            overload: ['java.lang.String','int','javax.net.SocketFactory','javax.net.ssl.SSLSocketFactory','javax.net.ssl.HostnameVerifier','com.android.okhttp.CertificatePinner','com.android.okhttp.Authenticator','java.net.Proxy','java.util.List','java.util.List','java.net.ProxySelector'],
            replacement: (m) => {
                const hv = Java.use('com.android.okhttp.internal.tls.OkHostnameVerifier').INSTANCE.value;
                const cp = Java.use('com.android.okhttp.CertificatePinner').DEFAULT.value;
                return function () { arguments[4] = hv; arguments[5] = cp; m.call(this, ...arguments); };
            }
        }
    ],
    'okhttp3.CertificatePinner': [
        { methodName: 'check',       overload: ['java.lang.String','java.util.List'],                      replacement: () => NO_OP },
        { methodName: 'check',       overload: ['java.lang.String','java.security.cert.Certificate'],      replacement: () => NO_OP },
        { methodName: 'check',       overload: ['java.lang.String','[Ljava.security.cert.Certificate;'],   replacement: () => NO_OP },
        { methodName: 'check$okhttp',                                                                       replacement: () => NO_OP },
    ],
    'com.squareup.okhttp.CertificatePinner': [
        { methodName: 'check', overload: ['java.lang.String','java.security.cert.Certificate'], replacement: () => NO_OP },
        { methodName: 'check', overload: ['java.lang.String','java.util.List'],                 replacement: () => NO_OP }
    ],
    'com.datatheorem.android.trustkit.pinning.PinningTrustManager': [
        { methodName: 'checkServerTrusted', replacement: () => NO_OP }
    ],
    'appcelerator.https.PinningTrustManager': [
        { methodName: 'checkServerTrusted', replacement: () => NO_OP }
    ],
    'nl.xservices.plugins.sslCertificateChecker': [
        {
            methodName: 'execute',
            overload: ['java.lang.String','org.json.JSONArray','org.apache.cordova.CallbackContext'],
            replacement: () => (_a, _b, ctx) => { ctx.success('CONNECTION_SECURE'); return true; }
        }
    ],
    'com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning': [
        { methodName: 'verify',   overload: '*', replacement: () => NO_OP }
    ],
    'com.worklight.androidgap.plugin.WLCertificatePinningPlugin': [
        { methodName: 'execute',  overload: '*', replacement: () => RETURN_TRUE }
    ],
    'com.commonsware.cwac.netsecurity.conscrypt.CertPinManager': [
        { methodName: 'isChainValid', overload: '*', replacement: () => RETURN_TRUE }
    ],
    'io.netty.handler.ssl.util.FingerprintTrustManagerFactory': [
        { methodName: 'checkTrusted', replacement: () => NO_OP }
    ],
    'com.silkimen.cordovahttp.CordovaServerTrust': [
        {
            methodName: '$init',
            replacement: (m) => function () {
                if (arguments[0] === 'pinned') arguments[0] = 'default';
                return m.call(this, ...arguments);
            }
        }
    ],
    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyHostnameVerifier': [
        { methodName: 'verify', replacement: () => RETURN_TRUE }
    ],
    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor': [
        { methodName: 'intercept', replacement: () => (a) => a.proceed(a.request()) }
    ],
    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager': [
        {
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;','java.lang.String'],
            replacement: () => NO_OP
        },
        {
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;','java.lang.String','java.lang.String'],
            replacement: () => (certs) => Java.use('java.util.Arrays').asList(certs)
        }
    ],
    'android.net.http.X509TrustManagerExtensions': [
        {
            methodName: 'checkServerTrusted',
            overload: '*',
            replacement: (m) => m.returnType.className === 'java.util.List'
                ? (certs) => Java.use('java.util.Arrays').asList(certs)
                : () => {}
        }
    ],
    'android.webkit.WebViewClient': [
        {
            methodName: 'onReceivedSslError',
            replacement: () => function (view, handler, error) { handler.proceed(); }
        }
    ]
};

// ── Apply all Java patches ────────────────────────────────────────────────
Java.perform(function () {
    console.log('[SSL✓] HTTP Toolkit Level bypass starting...');

    // 1. Known pinning libraries (25+ targets)
    Object.entries(PINNING_FIXES).forEach(([clsName, patches]) => {
        const Cls = _cls(clsName);
        if (!Cls) return;
        patches.forEach(({ methodName, getMethod, overload, replacement }) => {
            if (!replacement) return;
            const namedMethod = getMethod ? getMethod(Cls) : Cls[methodName];
            let impls = [];
            try {
                if (namedMethod) {
                    if (!overload)        impls = [namedMethod];
                    else if (overload === '*') impls = namedMethod.overloads;
                    else                  impls = [namedMethod.overload(...overload)];
                }
            } catch (e) {}
            impls.forEach((m) => {
                try {
                    m.implementation = replacement(m);
                    if (DEBUG_MODE) console.log(`[SSL✓] Patched ${clsName}.${methodName}`);
                } catch (e) {
                    console.log(`[SSL] Patch failed ${clsName}.${methodName}: ${e}`);
                }
            });
        });
    });
    console.log('[SSL✓] Known pinning libraries disabled (25+ targets)');

    // 1b. Proactive scan — hook ALL loaded TrustManager implementations
    try {
        const _Arrays = Java.use('java.util.Arrays');
        [
            '*!checkServerTrusted([Ljava.security.cert.X509Certificate;Ljava.lang.String;)/s',
            '*!checkServerTrusted([Ljava.security.cert.X509Certificate;Ljava.lang.String;Ljava.lang.String;)/s'
        ].forEach((sig, idx) => {
            Java.enumerateMethods(sig).forEach((group) => {
                if (group.name.startsWith('com.htk.bypass')) return;
                const Cls = _cls(group.name);
                if (!Cls) return;
                try {
                    const ov = idx === 0
                        ? Cls.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String')
                        : Cls.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String');
                    if (ov.implementation) return;
                    ov.implementation = idx === 0 ? () => {} : (certs) => _Arrays.asList(certs);
                    console.log(`[SSL✓] Proactive: ${group.name}.checkServerTrusted (sig${idx})`);
                } catch (e) {}
            });
        });
    } catch (e) { console.log('[SSL] Proactive scan error: ' + e); }

    // 2. Conscrypt TrustedCertificateIndex — intercept anchor lookups so all certs appear trusted
    [
        'com.android.org.conscrypt.TrustedCertificateIndex',
        'org.conscrypt.TrustedCertificateIndex',
        'org.apache.harmony.xnet.provider.jsse.TrustedCertificateIndex',
        'com.google.android.gms.org.conscrypt.TrustedCertificateIndex',
    ].forEach((clsName) => {
        const TCI = _cls(clsName);
        if (!TCI) return;
        try {
            // findAllSubjectX500Principals — return empty set so Conscrypt never rejects on principal
            if (TCI.findAllSubjectX500Principals) {
                TCI.findAllSubjectX500Principals.overload('java.security.cert.X509Certificate')
                    .implementation = function () { return Java.use('java.util.HashSet').$new(); };
            }
        } catch (e) {}
        try {
            // isTrusted variants — return first cert as a fake TrustAnchor hit
            ['isTrusted'].forEach((mName) => {
                if (!TCI[mName]) return;
                TCI[mName].overloads.forEach((ov) => {
                    try { ov.implementation = () => null; } catch (e) {}
                });
            });
            if (DEBUG_MODE) console.log(`[SSL✓] TrustedCertificateIndex hooked: ${clsName}`);
        } catch (e) {
            if (DEBUG_MODE) console.log(`[SSL] TCI hook failed ${clsName}: ${e}`);
        }
    });

    // 3. Fallback auto-patcher (mirrors android-certificate-unpinning-fallback.js)
    // Watches for SSL exceptions at runtime and patches the throwing method on-the-fly.
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const Arrays = Java.use('java.util.Arrays');
        const BASE_ARGS = ['[Ljava.security.cert.X509Certificate;', 'java.lang.String'];
        const EXT_ARGS  = ['[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'];

        const isX509TM = (cls, mName) =>
            mName === 'checkServerTrusted' && X509TrustManager.class.isAssignableFrom(cls.class);

        const isOkHttpPin = (msg, method) =>
            msg.startsWith('Certificate pinning failure!') &&
            method.argumentTypes.length === 2 &&
            method.argumentTypes[0].className === 'java.lang.String';

        const buildPatcher = (errCls, origCtor) => function (errArg) {
            try {
                const errMsg = errArg?.toString() ?? '';
                const stack  = Java.use('java.lang.Thread').currentThread().getStackTrace();
                const idx    = stack.findIndex(s => s.getClassName() === errCls);
                if (idx >= 0) {
                    const caller = stack[idx + 1];
                    const callerCls  = Java.use(caller.getClassName());
                    const callerMeth = caller.getMethodName();
                    const jMethod = callerCls[callerMeth];
                    if (jMethod) {
                        console.log(`[SSL✓] Auto-patching TLS failure: ${caller.getClassName()}->${callerMeth}`);
                        jMethod.overloads.forEach((ov) => {
                            if (ov.implementation) return;
                            if (isOkHttpPin(errMsg, ov)) {
                                ov.implementation = () => {};
                                console.log(`[SSL✓] Auto-patched OkHttp pinning: ${callerMeth}`);
                            } else if (isX509TM(callerCls, callerMeth)) {
                                const argTypes = ov.argumentTypes.map(t => t.className);
                                const retType  = ov.returnType.className;
                                if (argTypes.length === 2 && argTypes.every((t,i) => t === BASE_ARGS[i]) && retType === 'void') {
                                    ov.implementation = () => {};
                                    console.log(`[SSL✓] Auto-patched TrustManager base: ${callerMeth}`);
                                } else if (argTypes.length === 3 && argTypes.every((t,i) => t === EXT_ARGS[i]) && retType === 'java.util.List') {
                                    ov.implementation = (certs) => Arrays.asList(certs);
                                    console.log(`[SSL✓] Auto-patched TrustManager ext: ${callerMeth}`);
                                }
                            }
                        });
                    }
                }
            } catch (e) { if (DEBUG_MODE) console.log('[SSL] Auto-patcher error: ' + e); }
            return origCtor.call(this, ...arguments);
        };

        ['javax.net.ssl.SSLPeerUnverifiedException', 'java.security.cert.CertificateException'].forEach((ec) => {
            const EC = Java.use(ec);
            EC.$init.overloads.forEach((ov) => { ov.implementation = buildPatcher(ec, ov); });
        });
        console.log('[SSL✓] Fallback auto-patcher installed');
    } catch (e) { console.error('[SSL] Fallback patcher setup failed: ' + e); }

    console.log('[*] HTTP Toolkit Level Java SSL bypass complete');
});

// ── Native TLS layer (BoringSSL / Cronet) ────────────────────────────────
// Mirrors native-tls-hook.js: intercepts SSL_set_custom_verify /
// SSL_CTX_set_custom_verify and replaces the app's callback with a
// trust-all NativeCallback. Thread-safe via pending-set guard.
(function () {
    const SSL_VERIFY_OK = 0x0;

    function patchNativeLib(mod, libName) {
        const verifyAddrs = [
            mod.findExportByName('SSL_set_custom_verify'),
            mod.findExportByName('SSL_CTX_set_custom_verify'),
        ].filter(Boolean);

        if (!verifyAddrs.length) {
            if (DEBUG_MODE) console.log(`[SSL] No custom_verify exports in ${libName}`);
            return;
        }

        const cbCache = {};
        const buildTrustAllCb = (origAddr) => {
            const key = origAddr ? origAddr.toString() : '0';
            if (!cbCache[key]) {
                let pending = new Set();
                cbCache[key] = new NativeCallback(function (ssl, out_alert) {
                    const tid = Process.getCurrentThreadId();
                    const haveLock = pending.has(tid);
                    while (pending.size > 0 && !haveLock) { Thread.sleep(0.01); }
                    pending.add(tid);
                    if (!haveLock) pending.delete(tid);
                    return SSL_VERIFY_OK;
                }, 'int', ['pointer', 'pointer']);
            }
            return cbCache[key];
        };

        verifyAddrs.forEach((addr) => {
            const origFn = new NativeFunction(addr, 'void', ['pointer', 'int', 'pointer']);
            Interceptor.replace(origFn, new NativeCallback(function (ssl, mode, cbAddr) {
                origFn(ssl, mode, buildTrustAllCb(cbAddr));
            }, 'void', ['pointer', 'int', 'pointer']));
        });

        // Patch PSK identity (required by some BoringSSL builds)
        const pskAddr = mod.findExportByName('SSL_get_psk_identity');
        if (pskAddr) {
            Interceptor.replace(pskAddr, new NativeCallback(
                (ssl) => Memory.allocUtf8String('PSK_IDENTITY_PLACEHOLDER'),
                'pointer', ['pointer']
            ));
        }

        console.log(`[SSL✓] Native TLS patched: ${libName} (${verifyAddrs.length} verify hooks)`);
    }

    ['libssl.so', 'libboringssl.so', 'libsscronet.so', 'libssl_sb.so', 'libboringssl.dylib'].forEach((lib) => {
        waitForModule(lib, (mod) => patchNativeLib(mod, lib));
    });
})();
""",

    # ─────────────────────────────────────────────────────────────────────────
    # FLUTTER SSL UNPINNING
    # Source: https://github.com/httptoolkit/frida-interception-and-unpinning
    # Covers Flutter v2.0.0 – v3.32.0 on arm, arm64, x86, x64.
    # Defines waitForModule inline so it works standalone or combined.
    # ─────────────────────────────────────────────────────────────────────────
    "flutter_unpinning": r"""
// Flutter certificate unpinning
// Source: https://github.com/httptoolkit/frida-interception-and-unpinning
// Trust-all mode: accepts every certificate (no CERT_DER comparison)

(() => {
    const DEBUG_MODE = false;

    // Define waitForModule if not already available (standalone mode)
    if (typeof waitForModule === 'undefined') {
        const _F_CBS = {};
        globalThis.waitForModule = function waitForModule(name, cb) {
            try { cb(Process.getModuleByName(name)); return; } catch (e) {}
            try { cb(Module.load(name)); return; } catch (e) {}
            _F_CBS[name] = cb;
        };
        try {
            new ApiResolver('module').enumerateMatches('exports:linker*!*dlopen*').forEach((dl) => {
                Interceptor.attach(dl.address, {
                    onEnter(args) {
                        try { const s = args[0].readCString(); this.n = s ? s.slice(s.lastIndexOf('/') + 1) : ''; } catch (e) {}
                    },
                    onLeave(retval) {
                        if (!this.n || !retval || retval.isNull()) return;
                        const cb = _F_CBS[this.n];
                        if (!cb) return;
                        const mod = Process.findModuleByName(this.n) ?? Process.findModuleByAddress(retval);
                        if (mod) { cb(mod); delete _F_CBS[this.n]; }
                    }
                });
            });
        } catch (e) {}
    }

    const PATTERNS = {
    "android/x64": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "41 57 41 56 53 48 83 ec 10 b8 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 48 89 f3",
                "41 57 41 56 41 54 53 48 83 ec 18 b8 01 00 00 00 83 ff 01 0f 84 ?? ?? ?? ?? 48 89 f3"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "48 8b 47 50 c3",
                "48 8b 47 60 c3",
                "48 8b 87 a8 00 00 00 c3",
                "48 8b 87 b8 00 00 00 c3"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "41 56 53 50 48 89 f0 48 89 fb 48 89 e6 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0 7e 1b",
                "53 48 83 ec 10 48 89 f0 48 89 fb 48 8d 74 24 08 48 83 26 00 48 89 c7 e8 ?? ?? ?? ?? 85 c0",
                "41 56 53 48 83 ec 18 48 89 f0 48 89 fb 48 8d 74 24 08 48 83 26 00 48 89 c7 e8",
                "41 56 53 48 83 ec 18 48 89 f0 49 89 fe 48 8d 74 24 08 48 83 26 00 48 89 c7 e8",
                "41 57 41 56 53 48 83 ec 10 48 89 f0 49 89 fe 48 89 e6 48 83 26 00 48 89 c7 e8"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "55 41 56 53 48 83 ec 70 48 85 ff 0f 84 ?? ?? ?? ?? 48 89 f3 49 89 fe 48 8d 7c 24 40 6a 40",
                "48 8d 15 ?? ?? ?? ?? e9"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    },
    "android/x86": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "55 89 e5 53 57 56 83 e4 f0 83 ec 30 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? bf 01 00 00 00 83 7d 08 01 0f 84"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": [
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 2c 89 ec 5d c3",
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 34 89 ec 5d c3",
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 5c 89 ec 5d c3",
                "55 89 e5 83 e4 fc 8b 45 08 8b 40 64 89 ec 5d c3"
            ],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "55 89 e5 53 57 56 83 e4 f0 83 ec 10 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 08 83 20 00 83 ec 08 50 52",
                "55 89 e5 53 56 83 e4 f0 83 ec 10 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 0c 83 20 00 83 ec 08 50 52",
                "55 89 e5 53 57 56 83 e4 f0 83 ec 20 89 ce e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8d 44 24 14 83 20 00 89 44 24 04 89 14 24"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "55 89 e5 53 57 56 83 e4 f0 83 ec 40 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 8b 7d 08 85 ff 0f 84 ?? ?? ?? ?? 83 ec 08",
                "55 89 e5 53 83 e4 f0 83 ec 10 e8 ?? ?? ?? ?? 5b 81 c3 ?? ?? ?? ?? 83 ec 04 8d 83 ?? ?? ?? ?? 50 ff 75 0c ff 75 08"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    },
    "android/arm64": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 1f 04 00 71 c0 07 00 54 f3 03 01 aa ?? ?? ?? 94",
                "ff c3 00 d1 fe 57 01 a9 f4 4f 02 a9 1f 04 00 71 c0 02 00 54 f3 03 01 aa ?? ?? ?? 94"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": ["00 ?? ?? f9 c0 03 5f d6"],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "fe 0f 1e f8 f4 4f 01 a9 e1 ?? ?? 91 f3 03 08 aa ff 07 00 f9 ?? ?? ?? 97 1f 04 00 71",
                "fe 0f 1e f8 f4 4f 01 a9 e8 03 01 aa f3 03 00 aa e1 ?? ?? 91 e0 03 08 aa ff 07 00 f9",
                "ff 83 00 d1 fe 4f 01 a9 e1 ?? ?? 91 f3 03 08 aa ff 07 00 f9 ?? ?? ?? 97 1f 00 00 71",
                "ff c3 00 d1 fe 7f 01 a9 f4 4f 02 a9 e1 ?? ?? 91 f3 03 08 aa ?? ?? ?? 97 1f 00 00 71",
                "ff c3 00 d1 fe 7f 01 a9 f4 4f 02 a9 e1 ?? ?? 91 f3 03 08 aa ?? ?? ?? 97 1f 04 00 71"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "ff 43 02 d1 fe 57 07 a9 f4 4f 08 a9 a0 06 00 b4 f4 03 00 aa f3 03 01 aa e0 ?? ?? 91",
                "?2 ?? ?? ?? 42 ?? ?? 91 ?? ?? ?? 17"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    },
    "android/arm": {
        "dart::bin::SSLCertContext::CertificateCallback": {
            "signatures": [
                "70 b5 84 b0 01 28 02 d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 4d d0 20 46 ?? f? ?? f? 05 46 ?? f? ?? f",
                "70 b5 84 b0 01 28 02 d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 52 d0 20 46 ?? f? ?? f? 06 46 ?? f? ?? f",
                "70 b5 84 b0 01 28 02 d1 01 20 04 b0 70 bd 0c 46 ?? f? ?? f? 00 28 50 d0 20 46 ?? f? ?? f? 06 46 ?? f? ?? f"
            ]
        },
        "X509_STORE_CTX_get_current_cert": {
            "signatures": ["c0 6a 70 47","40 6b 70 47","c0 6d 70 47","40 6e 70 47"],
            "anchor": "dart::bin::SSLCertContext::CertificateCallback"
        },
        "bssl::x509_to_buffer": {
            "signatures": [
                "bc b5 00 25 0a 46 01 95 01 a9 04 46 10 46 ?? f? ?? f? 01 28 08 db 01 46 01 98 00 22 ?? f? ?? f? 05 46 01 98",
                "bc b5 00 25 0a 46 01 95 01 a9 04 46 10 46 ?? f? ?? f? 00 28 09 dd 01 46 01 98 00 22 ?? f? ?? f? 20 60 01 98",
                "7c b5 00 26 0a 46 01 96 01 a9 04 46 10 46 ?? f? ?? f? 00 28 0e dd 01 46 01 98 00 22 ?? f? ?? f? 05 46 01 98",
                "7c b5 00 26 0a 46 01 96 01 a9 04 46 10 46 ?? f? ?? f? 01 28 0d db 01 46 01 98 00 22 ?? f? ?? f? 05 46 01 98",
                "7c b5 00 26 0a 46 01 96 01 a9 04 46 10 46 ?? f? ?? f? 01 28 0e db 01 46 01 98 00 22 ?? f? ?? f? 05 46 00 90"
            ]
        },
        "i2d_X509": {
            "signatures": [
                "70 b5 8e b0 00 28 4f d0 05 46 08 a8 0c 46 40 21 ?? f? ?? f? 00 28 43 d0 2a 4a 08 a8 02 a9 ?? f? ?? f? e8 b3",
                "01 4a 7a 44 ?? f? ?? b"
            ],
            "anchor": "bssl::x509_to_buffer"
        }
    }
    };

    const MAX_ANCHOR_SCAN = 100;
    const CALL_MNEMONICS = ['call', 'bl', 'blx'];

    function scanForSig(base, size, patterns) {
        const results = [];
        for (const p of patterns) { results.push(...Memory.scanSync(base, size, p)); }
        return results;
    }

    function scanForFn(rxRanges, platPatterns, fnName, anchorFn) {
        const info = platPatterns[fnName];
        const sigs = info.signatures;
        if (info.anchor) {
            const maxLen = Math.max(...sigs.map(p => (p.length + 1) / 3));
            let addr = ptr(anchorFn);
            for (let i = 0; i < MAX_ANCHOR_SCAN; i++) {
                const instr = Instruction.parse(addr);
                addr = instr.next;
                if (CALL_MNEMONICS.includes(instr.mnemonic)) {
                    const target = ptr(instr.operands[0].value);
                    const res = scanForSig(target, maxLen, sigs);
                    if (res.length === 1) return res[0].address;
                    if (res.length > 1) throw new Error(`Multiple matches for ${fnName}`);
                }
            }
            throw new Error(`No match for ${fnName} anchored by ${anchorFn}`);
        } else {
            const results = rxRanges.flatMap(r => scanForSig(r.base, r.size, sigs));
            if (results.length !== 1 && sigs.length > 1) throw new Error(`Multiple matches for ${fnName}`);
            return results[0].address;
        }
    }

    function hookFlutter(modBase, modSize) {
        if (DEBUG_MODE) console.log('=== Disabling Flutter certificate pinning ===');
        const rxRanges = Process.enumerateRanges('r-x').filter(r =>
            r.base >= modBase && r.base < modBase.add(modSize)
        );
        try {
            const arch = Process.arch;
            const plat = PATTERNS[`android/${arch}`];
            if (!plat) { console.log(`[Flutter] No patterns for android/${arch}`); return; }

            const dartCb = new NativeFunction(
                scanForFn(rxRanges, plat, 'dart::bin::SSLCertContext::CertificateCallback'),
                'int', ['int', 'pointer']
            );
            const x509GetCert = new NativeFunction(
                scanForFn(rxRanges, plat, 'X509_STORE_CTX_get_current_cert', dartCb),
                'pointer', ['pointer']
            );
            const x509BufAddr = scanForFn(rxRanges, plat, 'bssl::x509_to_buffer');
            const i2d_X509 = new NativeFunction(
                scanForFn(rxRanges, plat, 'i2d_X509', x509BufAddr),
                'int', ['pointer', 'pointer']
            );

            Interceptor.attach(dartCb, {
                onEnter(args) { this.x509Store = args[1]; },
                onLeave(retval) {
                    if (retval.toInt32() === 1) return;
                    try {
                        // Trust-all: override any rejection with success
                        retval.replace(1);
                    } catch (e) {
                        console.error('[Flutter] Override error:', e);
                    }
                }
            });
            console.log('=== Flutter certificate pinning disabled ===');
        } catch (e) {
            console.error('[Flutter] Hook failed:', e);
        }
    }

    const flutter = Process.findModuleByName('libflutter.so');
    if (flutter) {
        hookFlutter(flutter.base, flutter.size);
    } else {
        waitForModule('libflutter.so', (mod) => hookFlutter(mod.base, mod.size));
    }
})();
""",

    # ─────────────────────────────────────────────────────────────────────────
    # SSL PINNING BYPASS (Basic)
    # ─────────────────────────────────────────────────────────────────────────
    "ssl_pinning": r"""
// Universal SSL Pinning Bypass
// Covers: TrustManager, OkHttp3 CertificatePinner, WebViewClient, HttpsURLConnection
Java.perform(function () {

    // 1. Custom TrustManager that accepts everything
    try {
        var TrustManager = Java.registerClass({
            name: 'com.bypass.UniversalTrustManager',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var tm = Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()]);
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, _tm, sr) {
            this.init(km, tm, sr);
        };
        console.log('[SSL] TrustManager bypass installed');
    } catch (e) { console.log('[SSL] TrustManager: ' + e); }

    // 2. OkHttp3 CertificatePinner
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
            console.log('[SSL] OkHttp3 CertificatePinner.check() bypassed');
        };
        CertPinner['check$okhttp'].implementation = function () {};
    } catch (e) { console.log('[SSL] OkHttp3 CertPinner: ' + e); }

    // 3. WebViewClient — suppress SSL errors
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log('[SSL] WebViewClient SSL error suppressed');
            handler.proceed();
        };
    } catch (e) { console.log('[SSL] WebViewClient: ' + e); }

    // 4. HttpsURLConnection hostname verifier
    try {
        var AllowAll = Java.registerClass({
            name: 'com.bypass.AllowAllVerifier',
            implements: [Java.use('javax.net.ssl.HostnameVerifier')],
            methods: { verify: function () { return true; } }
        });
        var HttpsConn = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsConn.setDefaultHostnameVerifier.implementation = function () {
            this.setDefaultHostnameVerifier(AllowAll.$new());
        };
    } catch (e) {}

    // 5. TrustKit (if present)
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation =
            function () { return true; };
    } catch (e) {}

    console.log('[*] SSL Pinning bypass complete');
});
""",

    # ─────────────────────────────────────────────────────────────────────────
    # ROOT DETECTION BYPASS
    # Source: https://github.com/httptoolkit/frida-interception-and-unpinning
    # ─────────────────────────────────────────────────────────────────────────
    "root_detection": r"""
/**************************************************************************************************
 * Root detection bypass — blocks file/package/command checks and system-property queries.
 * Source: https://github.com/httptoolkit/frida-interception-and-unpinning
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *************************************************************************************************/

(() => {
    const DEBUG_MODE = false;
    let _warned = false;
    function _log() { if (!_warned) { console.log(" => Blocked root detection (enable DEBUG_MODE for details)"); _warned = true; } }

    const LIB_C = Process.findModuleByName("libc.so");

    const BUILD_FP_REGEX = /^([\w.-]+\/[\w.-]+\/[\w.-]+):([\w.]+\/[\w.-]+\/[\w.-]+):(\w+\/[\w,.-]+)$/;
    const CONFIG = {
        secureProps: {
            "ro.secure": "1",
            "ro.debuggable": "0",
            "ro.build.type": "user",
            "ro.build.tags": "release-keys"
        }
    };

    const ROOT_INDICATORS = {
        paths: new Set([
            "/data/local/bin/su","/data/local/su","/data/local/xbin/su",
            "/dev/com.koushikdutta.superuser.daemon/","/sbin/su","/su/bin/su",
            "/system/bin/su","/system/xbin/su","/system/sbin/su","/vendor/bin/su",
            "/data/adb/su/bin/su","/system/bin/failsafe/su","/system/bin/.ext/.su",
            "/system/bin/.ext/su","/system/sd/xbin/su","/system/usr/we-need-root/su",
            "/cache/su","/data/su","/dev/su",
            "/data/adb/magisk","/sbin/.magisk","/cache/.disable_magisk",
            "/dev/.magisk.unblock","/cache/magisk.log","/data/adb/magisk.img",
            "/data/adb/magisk.db","/data/adb/magisk_simple","/init.magisk.rc",
            "/system/app/Superuser.apk","/system/etc/init.d/99SuperSUDaemon",
            "/system/xbin/daemonsu","/system/xbin/ku.sud",
            "/data/adb/ksu","/data/adb/ksud",
            "/system/xbin/busybox","/system/app/Kinguser.apk"
        ]),
        packages: new Set([
            "com.noshufou.android.su","com.noshufou.android.su.elite",
            "eu.chainfire.supersu","com.koushikdutta.superuser",
            "com.thirdparty.superuser","com.yellowes.su",
            "com.koushikdutta.rommanager","com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher","com.chelpus.lackypatch",
            "com.ramdroid.appquarantine","com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk","me.weishu.kernelsu"
        ]),
        commands: new Set([
            "su","which su","whereis su","locate su","find / -name su",
            "mount","magisk","/system/bin/su","/system/xbin/su","/sbin/su","/su/bin/su"
        ]),
        binaries: new Set(["su","busybox","magisk","supersu","ksud","daemonsu"])
    };

    function isRootPath(path) {
        if (!path) return false;
        const lp = path.toLowerCase();
        return ROOT_INDICATORS.paths.has(path) || lp.includes("magisk") || lp.includes("/su") || lp.endsWith("/su");
    }

    function bypassNativeFileCheck() {
        const fopen = LIB_C.findExportByName("fopen");
        if (fopen) Interceptor.attach(fopen, {
            onEnter(args) { this.path = args[0].readUtf8String(); },
            onLeave(retval) {
                if (retval.toInt32() !== 0 && isRootPath(this.path)) {
                    if (DEBUG_MODE) console.log(`Blocked fopen: ${this.path}`); else _log();
                    retval.replace(ptr(0x0));
                }
            }
        });
        const access = LIB_C.findExportByName("access");
        if (access) Interceptor.attach(access, {
            onEnter(args) { this.path = args[0].readUtf8String(); },
            onLeave(retval) {
                if (retval.toInt32() === 0 && isRootPath(this.path)) {
                    if (DEBUG_MODE) console.log(`Blocked access: ${this.path}`); else _log();
                    retval.replace(ptr(-1));
                }
            }
        });
        ["stat","lstat"].forEach((sym) => {
            const fn = LIB_C.findExportByName(sym);
            if (fn) Interceptor.attach(fn, {
                onEnter(args) { this.path = args[0].readUtf8String(); },
                onLeave(retval) {
                    if (isRootPath(this.path)) {
                        if (DEBUG_MODE) console.log(`Blocked ${sym}: ${this.path}`); else _log();
                        retval.replace(ptr(-1));
                    }
                }
            });
        });
    }

    function bypassJavaFileCheck() {
        const isRoot = (file) => {
            const path = file.getAbsolutePath();
            const name = file.getName();
            return ROOT_INDICATORS.paths.has(path) || path.includes("magisk") || name === "su";
        };
        const UnixFS = Java.use("java.io.UnixFileSystem");
        UnixFS.checkAccess.implementation = function (f, a) {
            if (isRoot(f)) { _log(); return false; } return this.checkAccess(f, a);
        };
        const File = Java.use("java.io.File");
        File.exists.implementation   = function () { if (isRoot(this)) { _log(); return false; } return this.exists(); };
        File.length.implementation   = function () { if (isRoot(this)) { _log(); return 0; }    return this.length(); };
        const FIS = Java.use("java.io.FileInputStream");
        FIS.$init.overload('java.io.File').implementation = function (f) {
            if (isRoot(f)) { _log(); throw Java.use("java.io.FileNotFoundException").$new(f.getAbsolutePath()); }
            return this.$init(f);
        };
    }

    function setProp() {
        const Build = Java.use("android.os.Build");
        const realFP = Build.FINGERPRINT.value;
        const m = BUILD_FP_REGEX.exec(realFP);
        let fp;
        if (m) {
            let [, device, versions, tags] = m;
            tags = 'user/release-keys';
            if (device.includes('generic') || device.includes('sdk') || device.includes('lineage')) device = 'google/raven/raven';
            fp = `${device}:${versions}:${tags}`;
        } else {
            fp = "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys";
        }
        ["TAGS","TYPE","FINGERPRINT"].forEach((f) => {
            const fld = Build.class.getDeclaredField(f === "FINGERPRINT" ? "FINGERPRINT" : f);
            fld.setAccessible(true);
            fld.set(null, f === "FINGERPRINT" ? fp : f === "TAGS" ? "release-keys" : "user");
        });
        const spg = LIB_C.findExportByName("__system_property_get");
        if (spg) Interceptor.attach(spg, {
            onEnter(args) { this.key = args[0].readCString(); this.ret = args[1]; },
            onLeave(retval) {
                const v = CONFIG.secureProps[this.key];
                if (v !== undefined) {
                    if (DEBUG_MODE) console.log(`Spoofed prop: ${this.key}`); else _log();
                    Memory.copy(this.ret, Memory.allocUtf8String(v), v.length + 1);
                }
            }
        });
    }

    function bypassRootPackageCheck() {
        const APM = Java.use("android.app.ApplicationPackageManager");
        APM.getPackageInfo.overload('java.lang.String','int').implementation = function (pkg, flags) {
            if (ROOT_INDICATORS.packages.has(pkg)) { _log(); pkg = "invalid.example.none"; }
            return this.getPackageInfo(pkg, flags);
        };
        APM.getInstalledPackages.overload('int').implementation = function (flags) {
            const pkgs = this.getInstalledPackages(flags);
            const arr = pkgs.toArray().filter(p => !ROOT_INDICATORS.packages.has(p.packageName?.value));
            return Java.use("java.util.ArrayList").$new(Java.use("java.util.Arrays").asList(arr));
        };
    }

    function bypassShellCommands() {
        const PB = Java.use('java.lang.ProcessBuilder');
        PB.command.overload('java.util.List').implementation = function (cmds) {
            const a = cmds.toArray();
            if (a.length > 0 && (ROOT_INDICATORS.commands.has(a[0].toString()) || (a.length > 1 && ROOT_INDICATORS.binaries.has(a[1].toString())))) {
                _log(); return this.command(Java.use("java.util.Arrays").asList([""]));
            }
            return this.command(cmds);
        };
        const RT = Java.use('java.lang.Runtime');
        RT.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
            if (arr.length > 0 && ROOT_INDICATORS.commands.has(arr[0])) { _log(); return this.exec([""]); }
            return this.exec(arr);
        };
        try {
            const PI = Java.use("java.lang.ProcessImpl");
            PI.start.implementation = function (arr, env, dir, red, redir) {
                if (arr.length > 0 && ROOT_INDICATORS.commands.has(arr[0].toString())) {
                    _log(); return PI.start.call(this, [Java.use("java.lang.String").$new("")], env, dir, red, redir);
                }
                return PI.start.call(this, arr, env, dir, red, redir);
            };
        } catch (e) {}
    }

    try {
        bypassNativeFileCheck();
        Java.perform(function () {
            try {
                bypassJavaFileCheck();
                setProp();
                bypassRootPackageCheck();
                bypassShellCommands();
                console.log("== Disabled Android root detection ==");
            } catch (e) { console.error("!!! Java root bypass error:", e); }
        });
    } catch (e) { console.error("!!! Native root bypass error:", e); }
})();
""",

    # ─────────────────────────────────────────────────────────────────────────
    # BIOMETRIC / AUTHENTICATION BYPASS
    # ─────────────────────────────────────────────────────────────────────────
    "biometric_bypass": r"""
// Biometric & Authentication Bypass
// Covers: BiometricPrompt (API 28+), FingerprintManager (API 23-28), KeyguardManager
Java.perform(function () {

    // 1. BiometricPrompt (API 28+)
    try {
        var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
        BiometricPrompt.authenticate.overload(
            'android.os.CancellationSignal',
            'java.util.concurrent.Executor',
            'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback'
        ).implementation = function (signal, executor, callback) {
            console.log('[Auth] BiometricPrompt.authenticate() intercepted → triggering success');
            var AuthResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
            callback.onAuthenticationSucceeded(AuthResult.$new(null, null));
        };
        console.log('[Auth] BiometricPrompt bypass active');
    } catch (e) { console.log('[Auth] BiometricPrompt: ' + e); }

    // 2. FingerprintManager (API 23-28)
    try {
        var FPM = Java.use('android.hardware.fingerprint.FingerprintManager');
        FPM.authenticate.overload(
            'android.hardware.fingerprint.FingerprintManager$CryptoObject',
            'android.os.CancellationSignal', 'int',
            'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
            'android.os.Handler'
        ).implementation = function (crypto, cancel, flags, callback, handler) {
            console.log('[Auth] FingerprintManager.authenticate() → triggering success');
            var FPResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
            callback.onAuthenticationSucceeded(FPResult.$new(null));
        };
        console.log('[Auth] FingerprintManager bypass active');
    } catch (e) { console.log('[Auth] FingerprintManager: ' + e); }

    // 3. KeyguardManager
    try {
        var KM = Java.use('android.app.KeyguardManager');
        KM.isKeyguardSecure.implementation  = function () { return false; };
        KM.isDeviceSecure.implementation    = function () { return false; };
        KM.isKeyguardLocked.implementation  = function () { return false; };
        console.log('[Auth] KeyguardManager spoofed');
    } catch (e) {}

    console.log('[*] Biometric/Auth bypass complete');
});
""",

    # ─────────────────────────────────────────────────────────────────────────
    # ANTI-DEBUGGING BYPASS
    # ─────────────────────────────────────────────────────────────────────────
    "anti_debug": r"""
// Anti-Debugging Bypass
// Covers: Debug API, ptrace, TracerPid, ActivityManager.isUserAMonkey
Java.perform(function () {

    // 1. android.os.Debug
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation  = function () { return false; };
        Debug.waitingForDebugger.implementation   = function () { return false; };
        console.log('[AntiDebug] android.os.Debug spoofed');
    } catch (e) {}

    // 2. ActivityManager.isUserAMonkey
    try {
        var AM = Java.use('android.app.ActivityManager');
        AM.isUserAMonkey.implementation = function () { return false; };
    } catch (e) {}

    // 3. ptrace PTRACE_TRACEME (native)
    try {
        var ptrace = Module.findExportByName('libc.so', 'ptrace');
        if (ptrace) {
            Interceptor.attach(ptrace, {
                onEnter: function (args) {
                    if (args[0].toInt32() === 0) {
                        args[0] = ptr(-1);
                        console.log('[AntiDebug] PTRACE_TRACEME blocked');
                    }
                }
            });
        }
    } catch (e) {}

    // 4. Spoof /proc/self/status TracerPid
    try {
        var BR = Java.use('java.io.BufferedReader');
        BR.readLine.implementation = function () {
            var line = this.readLine();
            if (line !== null && line.indexOf('TracerPid') !== -1) {
                console.log('[AntiDebug] TracerPid spoofed → 0');
                return 'TracerPid:\t0';
            }
            return line;
        };
    } catch (e) {}

    console.log('[*] Anti-debug bypass complete');
});
""",

    # ─────────────────────────────────────────────────────────────────────────
    # NETWORK TRAFFIC LOGGER
    # ─────────────────────────────────────────────────────────────────────────
    "network_logger": r"""
// Network Traffic Logger
// Covers: OkHttp3, HttpURLConnection
Java.perform(function () {

    // 1. OkHttp3 network interceptor
    try {
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');
        Builder.build.implementation = function () {
            try {
                var Interceptor = Java.use('okhttp3.Interceptor');
                var logger = Java.implement(Interceptor, {
                    intercept: function (chain) {
                        var req    = chain.request();
                        var url    = req.url().toString();
                        var method = req.method();
                        console.log('[Net] >> ' + method + '  ' + url);

                        var hdrs = req.headers();
                        for (var i = 0; i < hdrs.size(); i++) {
                            console.log('[Net]    ' + hdrs.name(i) + ': ' + hdrs.value(i));
                        }
                        if (req.body() !== null) {
                            try {
                                var buf = Java.use('okio.Buffer').$new();
                                req.body().writeTo(buf);
                                var body = buf.readUtf8();
                                if (body.length > 0) console.log('[Net]    Body: ' + body);
                            } catch (e) {}
                        }

                        var resp = chain.proceed(req);
                        console.log('[Net] << ' + resp.code() + '  ' + url);
                        return resp;
                    }
                });
                this.addNetworkInterceptor(logger);
            } catch (e) { console.log('[Net] Interceptor attach error: ' + e); }
            return this.build();
        };
        console.log('[Net] OkHttp3 logger active');
    } catch (e) { console.log('[Net] OkHttp3 not found'); }

    // 2. HttpURLConnection.openConnection
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            console.log('[Net] HttpURLConnection → ' + this.toString());
            return this.openConnection();
        };
    } catch (e) {}

    console.log('[*] Network logger loaded');
});
""",

    # ─────────────────────────────────────────────────────────────────────────
    # PROXY TRAFFIC REDIRECT
    # Source: native-connect-hook.js + android-proxy-override.js
    #         https://github.com/httptoolkit/frida-interception-and-unpinning
    #
    # Redirects ALL TCP connections at the native socket level to a proxy
    # (Burp Suite / HTTP Toolkit / Proxyman / Charles).
    # Critical for Flutter, Cronet, and any app that ignores system proxy.
    # Set %%PROXY_HOST%%:%%PROXY_PORT%% via the UI fields before launching.
    # ─────────────────────────────────────────────────────────────────────────
    "proxy_redirect": r"""
// ═══════════════════════════════════════════════════════════════════════════
// Proxy Traffic Redirect — forces ALL TCP through your interception proxy
// Sources: native-connect-hook.js + android-proxy-override.js
//          https://github.com/httptoolkit/frida-interception-and-unpinning
// ═══════════════════════════════════════════════════════════════════════════

const PROXY_HOST = '%%PROXY_HOST%%';
const PROXY_PORT = %%PROXY_PORT%%;
const IGNORED_NON_HTTP_PORTS = [];
const BLOCK_HTTP3 = true;
const PROXY_SUPPORTS_SOCKS5 = false;
const DEBUG_MODE = false;

// ── Java proxy system properties (android-proxy-override.js) ─────────────
Java.perform(() => {
    const System = Java.use('java.lang.System');
    System.setProperty('http.proxyHost',  PROXY_HOST);
    System.setProperty('http.proxyPort',  PROXY_PORT.toString());
    System.setProperty('https.proxyHost', PROXY_HOST);
    System.setProperty('https.proxyPort', PROXY_PORT.toString());
    try { System.clearProperty('http.nonProxyHosts');  } catch (e) {}
    try { System.clearProperty('https.nonProxyHosts'); } catch (e) {}

    const controlled = ['http.proxyHost','http.proxyPort','https.proxyHost','https.proxyPort',
                        'http.nonProxyHosts','https.nonProxyHosts'];
    System.clearProperty.implementation = function (prop) {
        if (controlled.includes(prop)) return this.getProperty(prop);
        return this.clearProperty(...arguments);
    };
    System.setProperty.implementation = function (prop) {
        if (controlled.includes(prop)) return this.getProperty(prop);
        return this.setProperty(...arguments);
    };

    try {
        const ProxyInfo = Java.use('android.net.ProxyInfo');
        const ConnMgr   = Java.use('android.net.ConnectivityManager');
        ConnMgr.getDefaultProxy.implementation = () => ProxyInfo.$new(PROXY_HOST, PROXY_PORT, '');
    } catch (e) {}

    try {
        const Collections = Java.use('java.util.Collections');
        const ProxyType   = Java.use('java.net.Proxy$Type');
        const InetSA      = Java.use('java.net.InetSocketAddress');
        const ProxyCls    = Java.use('java.net.Proxy');
        const ProxySelector = Java.use('java.net.ProxySelector');
        const targetProxy = ProxyCls.$new(ProxyType.HTTP.value, InetSA.$new(PROXY_HOST, PROXY_PORT));
        const getList     = () => Collections.singletonList(targetProxy);
        Java.enumerateMethods('*!select(java.net.URI): java.util.List/s')
            .flatMap(l => l.classes.map(c => Java.use(c.name)))
            .filter(C => ProxySelector.class.isAssignableFrom(C.class))
            .forEach(C => { C.select.implementation = () => getList(); });
    } catch (e) {}

    console.log(`[Proxy] Java proxy → ${PROXY_HOST}:${PROXY_PORT}`);
});

// ── Native connect() hook (native-connect-hook.js) ────────────────────────
// Intercepts every TCP connect() call and rewrites the destination to the
// proxy address. Essential for Flutter, Cronet, and hard-coded hostnames.
(() => {
    const PROXY_HOST_IPv4 = PROXY_HOST.split('.').map(p => parseInt(p, 10));
    const IPv6_PREFIX = [0,0,0,0,0,0,0,0,0,0,0xff,0xff];
    const PROXY_HOST_IPv6 = IPv6_PREFIX.concat(PROXY_HOST_IPv4);

    const F_GETFL = 3, F_SETFL = 4;
    const O_NONBLOCK = 2048; // Linux/Android

    let fcntl, sendFn, recvFn, connAddr;
    try {
        const libc = Process.findModuleByName('libc.so') ?? Process.findModuleByName('libc.so.6');
        if (!libc) { console.error('[Proxy] libc not found — connect hook skipped'); return; }
        fcntl   = new NativeFunction(libc.getExportByName('fcntl'),  'int',     ['int','int','int']);
        sendFn  = new NativeFunction(libc.getExportByName('send'),   'ssize_t', ['int','pointer','size_t','int']);
        recvFn  = new NativeFunction(libc.getExportByName('recv'),   'ssize_t', ['int','pointer','size_t','int']);
        connAddr = libc.getExportByName('connect');
    } catch (e) { console.error('[Proxy] connect hook setup failed:', e.message); return; }

    const areEqual = (a, b) => a.length === b.length && a.every((x, i) => b[i] === x);

    Interceptor.attach(connAddr, {
        onEnter(args) {
            const fd       = this.sockFd = args[0].toInt32();
            const sockType = Socket.type(fd);
            const addrPtr  = ptr(args[1]);
            const addrLen  = args[2].toInt32();
            const addrData = addrPtr.readByteArray(addrLen);

            const isTCP  = sockType === 'tcp'  || sockType === 'tcp6';
            const isUDP  = sockType === 'udp'  || sockType === 'udp6';
            const isIPv6 = sockType === 'tcp6' || sockType === 'udp6';

            if (!isTCP && !isUDP) { this.state = 'ignored'; return; }

            const portDV  = new DataView(addrData.slice(2, 4));
            const port    = portDV.getUint16(0, false);

            const ignored  = IGNORED_NON_HTTP_PORTS.includes(port);
            const blocked  = BLOCK_HTTP3 && !ignored && isUDP && port === 443;
            const intercept = isTCP && !ignored && !blocked;

            const hostBytes = isIPv6
                ? new Uint8Array(addrData.slice(8, 24))
                : new Uint8Array(addrData.slice(4, 8));

            const alreadyProxy = port === PROXY_PORT &&
                areEqual(hostBytes, isIPv6 ? PROXY_HOST_IPv6 : PROXY_HOST_IPv4);
            if (alreadyProxy) { this.state = 'ignored'; return; }

            if (blocked) {
                if (isIPv6) { for (let i = 0; i < 16; i++) addrPtr.add(8+i).writeU8(0); }
                else         { addrPtr.add(4).writeU32(0); }
                this.state = 'blocked';
                if (DEBUG_MODE) console.log(`[Proxy] Blocked QUIC :${port}`);
            } else if (intercept) {
                this.state = 'intercepting';
                if (PROXY_SUPPORTS_SOCKS5) {
                    this.origDest = { host: hostBytes, port, isIPv6 };
                    this.origFlags = fcntl(fd, F_GETFL, 0);
                    this.nonBlocking = (this.origFlags & O_NONBLOCK) !== 0;
                    if (this.nonBlocking) fcntl(fd, F_SETFL, this.origFlags & ~O_NONBLOCK);
                }
                // Rewrite port
                portDV.setUint16(0, PROXY_PORT, false);
                addrPtr.add(2).writeByteArray(portDV.buffer);
                // Rewrite address
                if (isIPv6) addrPtr.add(8).writeByteArray(PROXY_HOST_IPv6);
                else        addrPtr.add(4).writeByteArray(PROXY_HOST_IPv4);
                console.log(`[Proxy] Redirecting TCP :${port} → ${PROXY_HOST}:${PROXY_PORT}`);
            } else {
                this.state = 'ignored';
            }
        },
        onLeave(retval) {
            if (this.state !== 'intercepting' || !PROXY_SUPPORTS_SOCKS5) return;
            const ok = retval.toInt32() === 0;
            let success = false;
            if (ok) {
                const { host, port, isIPv6 } = this.origDest;
                success = _socks5Handshake(this.sockFd, host, port, isIPv6);
            }
            if (this.nonBlocking) fcntl(this.sockFd, F_SETFL, this.origFlags);
            if (!success) retval.replace(-1); else retval.replace(0);
        }
    });

    function _socks5Handshake(fd, hostBytes, port, isIPv6) {
        const hello = Memory.alloc(3).writeByteArray([0x05, 0x01, 0x00]);
        if (sendFn(fd, hello, 3, 0) < 0) return false;
        const resp = Memory.alloc(2);
        if (recvFn(fd, resp, 2, 0) < 0) return false;
        if (resp.readU8() !== 0x05 || resp.add(1).readU8() !== 0x00) return false;
        const req = [0x05, 0x01, 0x00, isIPv6 ? 0x04 : 0x01,
                     ...hostBytes, (port >> 8) & 0xff, port & 0xff];
        const reqBuf = Memory.alloc(req.length).writeByteArray(req);
        if (sendFn(fd, reqBuf, req.length, 0) < 0) return false;
        const replyHdr = Memory.alloc(4);
        if (recvFn(fd, replyHdr, 4, 0) < 0) return false;
        if (replyHdr.add(1).readU8() !== 0x00) return false;
        const atyp = replyHdr.add(3).readU8();
        const rem  = atyp === 0x01 ? 6 : atyp === 0x04 ? 18 : 0;
        if (rem > 0) recvFn(fd, Memory.alloc(rem), rem, 0);
        return true;
    }

    console.log(`[Proxy] Native connect() hook active → all TCP → ${PROXY_HOST}:${PROXY_PORT}`);
})();
""",

    # ─────────────────────────────────────────────────────────────────────────
    # METHOD TRACER
    # ─────────────────────────────────────────────────────────────────────────
    "method_tracer": r"""
// Method Tracer — hooks all methods of %%TARGET_CLASS%%
Java.perform(function () {
    var className = '%%TARGET_CLASS%%';
    try {
        var klass   = Java.use(className);
        var methods = klass.class.getDeclaredMethods();
        var hooked  = 0;
        methods.forEach(function (m) {
            var name = m.getName();
            try {
                klass[name].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = [].slice.call(arguments).map(function (a) {
                            try { return a !== null && a !== undefined ? a.toString() : 'null'; }
                            catch (e) { return '?'; }
                        });
                        console.log('[Trace] ' + name + '(' + args.join(', ') + ')');
                        var ret = this[name].apply(this, arguments);
                        console.log('[Trace]   → ' + ret);
                        return ret;
                    };
                    hooked++;
                });
            } catch (e) {}
        });
        console.log('[*] Tracing ' + hooked + ' overloads on ' + className);
    } catch (e) {
        console.log('[Tracer] Class not found: ' + className + ' — ' + e);
    }
});
""",
}


# ── ADB helper (shared with ADBWorker) ───────────────────────────────────────

def _get_adb_cmd() -> str:
    project_root = Path(__file__).parent.parent
    pt_dir       = project_root / "tools" / "platform-tools"
    adb_name     = "adb.exe" if os.name == "nt" else "adb"
    bundled      = pt_dir / adb_name
    if bundled.exists():
        pt_str  = str(pt_dir)
        current = os.environ.get("PATH", "")
        if pt_str not in current:
            os.environ["PATH"] = pt_str + os.pathsep + current
        return str(bundled)
    return "adb"


# ── Worker ───────────────────────────────────────────────────────────────────

class FridaWorker(QThread):
    """Worker thread for all Frida operations."""
    finished = pyqtSignal(dict)
    error    = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, operation: str, *args, device_serial: str = ""):
        super().__init__()
        self.operation     = operation
        self.args          = args
        self.device_serial = device_serial
        self._proc         = None   # subprocess.Popen reference (for stop())
        self._resolved_serial: str | None = None  # cached for duration of run()

    # ------------------------------------------------------------------
    # Thread entry
    # ------------------------------------------------------------------

    def run(self):
        dispatch = {
            "check_frida":    self._check_frida,
            "setup_server":   self._setup_server,
            "list_processes": self._list_processes,
            "run_frida":      self._run_frida,
        }
        try:
            fn = dispatch.get(self.operation)
            if fn is None:
                raise Exception(f"Unknown Frida operation: {self.operation}")
            result = fn()
            if not self.isInterruptionRequested():
                self.finished.emit(result)
        except Exception as e:
            if not self.isInterruptionRequested():
                self.error.emit(str(e))

    def stop(self):
        """Terminate the underlying Frida subprocess and signal the thread to exit."""
        self.requestInterruption()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_serial(self) -> str:
        """Validate stored serial against live 'adb devices'; auto-pick if stale.
        Result is cached for the lifetime of this worker run() call."""
        if self._resolved_serial is not None:
            return self._resolved_serial
        adb = _get_adb_cmd()
        try:
            r = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=10)
            live = []
            for line in r.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "device":
                    live.append(parts[0])
            if not live:
                serial = self.device_serial  # nothing connected — adb will report the error
            elif self.device_serial and self.device_serial in live:
                serial = self.device_serial  # stored serial still valid
            elif len(live) == 1:
                serial = live[0]             # only one device — use it regardless of stored serial
            else:
                serial = ""                  # multiple devices, none matching — let adb complain
        except Exception:
            serial = self.device_serial
        self._resolved_serial = serial
        return serial

    def _adb(self, *args) -> list:
        cmd = [_get_adb_cmd()]
        serial = self._resolve_serial()
        if serial:
            cmd += ["-s", serial]
        return cmd + list(args)

    def _run_adb(self, *args, timeout: int = 30) -> str:
        r = subprocess.run(self._adb(*args), capture_output=True, text=True,
                           timeout=timeout, shell=False)
        return (r.stdout + r.stderr).strip()

    def _frida_device_args(self) -> list:
        serial = self._resolve_serial()
        return ["-D", serial] if serial else ["-U"]

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def _check_frida(self) -> dict:
        info = {
            "frida_installed": False,
            "frida_version":   "",
            "server_running":  False,
            "server_pid":      "",
        }
        # Check frida CLI
        try:
            r = subprocess.run(["frida", "--version"], capture_output=True,
                               text=True, timeout=10)
            if r.returncode == 0:
                info["frida_installed"] = True
                info["frida_version"]   = r.stdout.strip()
                self.progress.emit(f"frida-tools {r.stdout.strip()} found")
        except FileNotFoundError:
            self.progress.emit("frida-tools not found — install: pip install frida-tools")
            return info
        except Exception as e:
            self.progress.emit(f"frida check error: {e}")
            return info

        # Check frida-server on device
        try:
            ps_out = self._run_adb("shell", "ps", "-e")
            lines  = [l for l in ps_out.splitlines() if "frida-server" in l]
            if lines:
                info["server_running"] = True
                parts = lines[0].split()
                info["server_pid"] = parts[1] if len(parts) > 1 else ""
                self.progress.emit(f"frida-server running (PID {info['server_pid']})")
            else:
                self.progress.emit("frida-server is NOT running on device")
        except Exception as e:
            self.progress.emit(f"Could not check frida-server: {e}")

        return info

    def _setup_server(self) -> dict:
        """Download the matching frida-server binary, push via ADB, and start it."""
        # 1. Device arch
        self.progress.emit("Detecting device architecture...")
        arch_raw = self._run_adb("shell", "getprop", "ro.product.cpu.abi")
        self.progress.emit(f"Device ABI: {arch_raw}")
        if not arch_raw or "error" in arch_raw.lower() or "not found" in arch_raw.lower():
            raise Exception(
                f"Cannot reach device (adb returned: {arch_raw!r}).\n"
                "Check USB connection and that the device is authorised."
            )
        arch = {
            "arm64-v8a":   "arm64",
            "armeabi-v7a": "arm",
            "x86_64":      "x86_64",
            "x86":         "x86",
        }.get(arch_raw.strip(), "arm64")

        # 2. Frida version
        self.progress.emit("Resolving frida version...")
        try:
            r = subprocess.run(["frida", "--version"], capture_output=True,
                               text=True, timeout=10)
            version = r.stdout.strip()
        except FileNotFoundError:
            raise Exception("frida-tools not installed.\nRun:  pip install frida-tools")

        # 3. Download frida-server (cached in tools/frida/)
        server_dir  = Path(__file__).parent.parent / "tools" / "frida"
        server_dir.mkdir(parents=True, exist_ok=True)
        server_path = server_dir / f"frida-server-{version}-{arch}"

        if not server_path.exists():
            url = (
                f"https://github.com/frida/frida/releases/download/"
                f"{version}/frida-server-{version}-android-{arch}.xz"
            )
            self.progress.emit(f"Downloading frida-server {version} for {arch}...")
            xz_path = server_dir / f"frida-server-{version}-android-{arch}.xz"
            try:
                urllib.request.urlretrieve(url, str(xz_path))
                self.progress.emit("Download complete. Extracting .xz...")
                with lzma.open(str(xz_path), "rb") as f_in:
                    server_path.write_bytes(f_in.read())
                xz_path.unlink(missing_ok=True)
                self.progress.emit(f"Cached at: {server_path}")
            except Exception as e:
                raise Exception(f"Download failed: {e}\nURL tried: {url}")
        else:
            self.progress.emit(f"Using cached binary: {server_path.name}")

        # 4. Push to device
        self.progress.emit("Pushing frida-server to /data/local/tmp/...")
        out = self._run_adb("push", str(server_path), "/data/local/tmp/frida-server", timeout=120)
        self.progress.emit(out or "push OK")

        # 5. chmod 755
        self._run_adb("shell", "chmod", "755", "/data/local/tmp/frida-server")
        self.progress.emit("Permissions set (755)")

        # 6. Kill any old instance
        self._run_adb("shell", "su -c 'pkill -9 -f frida-server 2>/dev/null; true' 2>/dev/null || pkill -9 -f frida-server 2>/dev/null; true")
        time.sleep(0.5)

        # 7. Start in background — nohup+& daemonises on the device so the
        #    adb shell session can close without killing frida-server.
        self.progress.emit("Starting frida-server...")
        start_cmd = (
            "su -c 'nohup /data/local/tmp/frida-server > /dev/null 2>&1 &' 2>/dev/null"
            " || nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"
        )
        self._run_adb("shell", start_cmd, timeout=10)

        # 8. Verify — retry a few times; ps flag varies by Android version
        self.progress.emit("Verifying frida-server started...")
        running = False
        for attempt in range(6):
            time.sleep(1)
            ps_out = self._run_adb("shell", "ps -A 2>/dev/null || ps -e 2>/dev/null || ps")
            if "frida-server" in ps_out:
                running = True
                break
        if not running:
            raise Exception(
                "frida-server did not appear in process list.\n"
                "The device may require root (su) to run frida-server.\n"
                "Try manually: adb shell su -c 'nohup /data/local/tmp/frida-server > /dev/null 2>&1 &'"
            )

        self.progress.emit("✓ frida-server is running!")
        return {"success": True, "version": version, "arch": arch}

    def _list_processes(self) -> dict:
        """List running processes via frida-ps."""
        try:
            cmd = ["frida-ps"] + self._frida_device_args() + ["-ai"]
            r   = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if r.returncode != 0:
                raise Exception(r.stderr.strip() or "frida-ps failed")
            lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            return {"processes": lines}
        except FileNotFoundError:
            raise Exception("frida-tools not installed.\nRun:  pip install frida-tools")

    def _run_frida(self) -> dict:
        """
        Run Frida against a target package with combined scripts.
        args[0] : package name (str)
        args[1] : list of JS script strings
        args[2] : mode — "spawn" | "attach"
        """
        package = str(self.args[0])
        scripts = list(self.args[1])
        mode    = str(self.args[2]) if len(self.args) > 2 else "spawn"

        if not package:
            raise Exception("No target package specified.")
        if not scripts:
            raise Exception("No scripts selected.")

        combined = "\n\n// ─────────────────────────────────────────\n\n".join(scripts)

        # Write combined script to a temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False, encoding="utf-8"
        ) as f:
            f.write(combined)
            script_path = f.name

        self.progress.emit(f"Target  : {package}")
        self.progress.emit(f"Mode    : {mode}")
        self.progress.emit(f"Scripts : {len(scripts)} injected ({len(combined)} bytes)")

        try:
            cmd = ["frida"] + self._frida_device_args()
            if mode == "spawn":
                cmd += ["-f", package]
            else:
                # -N = attach by package identifier (correct for Android in Frida 12+)
                cmd += ["-N", package]
            # -q = no REPL prompt, -t inf = run forever (don't exit after script loads)
            cmd += ["-l", script_path, "-q", "-t", "inf"]

            self.progress.emit("Launching Frida... (use Stop to terminate)")
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            # Stream output line by line until process ends or thread is interrupted
            for line in iter(self._proc.stdout.readline, ""):
                if self.isInterruptionRequested():
                    break
                stripped = line.rstrip()
                if stripped:
                    self.progress.emit(stripped)

            self._proc.stdout.close()
            self._proc.wait()

        finally:
            try:
                Path(script_path).unlink()
            except Exception:
                pass

        return {"package": package, "mode": mode, "exited": True}
