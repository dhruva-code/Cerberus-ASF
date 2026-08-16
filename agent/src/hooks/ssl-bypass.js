/**
 * SSL/TLS pinning bypass. The original hook only covered Conscrypt's
 * TrustManagerImpl — apps using OkHttp's own CertificatePinner (which the
 * static engine's CERBERUS-DEF-01 rule explicitly detects as common) validate
 * pins independently of the platform trust manager and defeat that hook
 * alone. Both are hooked here.
 */
export function installSslBypass(Java, send) {
    Java.perform(() => {
        try {
            const ArrayList = Java.use("java.util.ArrayList");
            const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TrustManagerImpl.checkTrustedRecursive.implementation = function (
                certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used
            ) {
                send({ level: "warning", message: "[Frida] Intercepted SSL handshake for host: " + host + " (Conscrypt TrustManager Bypassed)" });
                return ArrayList.$new();
            };
        } catch (e) {
            // Not present on this ART/Conscrypt build — silently continue to the next technique.
        }

        try {
            const CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
                send({ level: "warning", message: "[Frida] Intercepted OkHttp CertificatePinner.check for host: " + hostname + " (Pinning Bypassed)" });
                return;
            };
        } catch (e) {
            // App doesn't bundle OkHttp, or uses a CertificatePinner overload not covered here.
        }

        send({ level: "crypto", message: "[Frida] SSL Trust Validation neutralized. Traffic is interceptable." });
    });
}
