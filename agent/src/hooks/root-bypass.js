/**
 * Root/jailbreak detection bypass. Covers more than the original
 * File.exists()/Runtime.exec(String) pair — those alone are defeated by
 * any detector using Runtime.exec(String[]), ProcessBuilder, or a
 * Build.TAGS check (e.g. RootBeer, which the static engine's own
 * CERBERUS-DEF-02 rule explicitly detects).
 */
const ROOT_PATHS = [
    "/data/local/", "/data/local/bin/", "/data/local/xbin/",
    "/sbin/", "/su/bin/", "/system/bin/", "/system/bin/.ext/",
    "/system/bin/failsafe/", "/system/sd/xbin/", "/system/xbin/",
];

function looksLikeRootCommand(cmd) {
    return cmd.indexOf("su") > -1 || cmd.indexOf("magisk") > -1 || cmd.indexOf("busybox") > -1;
}

function isSuspiciousPath(path) {
    if (path.indexOf("magisk") > -1) return true;
    return ROOT_PATHS.some((p) => path.indexOf(p + "su") > -1);
}

export function installRootBypass(Java, send) {
    Java.perform(() => {
        const File = Java.use("java.io.File");
        File.exists.implementation = function () {
            const path = this.getAbsolutePath();
            if (isSuspiciousPath(path)) {
                send({ level: "crypto", message: "[Frida] Root check intercepted and spoofed: " + path });
                return false;
            }
            return this.exists();
        };

        const Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if (looksLikeRootCommand(cmd)) {
                send({ level: "crypto", message: "[Frida] Root terminal command blocked: " + cmd });
                cmd = "just_a_fake_command";
            }
            return this.exec(cmd);
        };

        try {
            Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
                const joined = cmdArray.join(" ");
                if (looksLikeRootCommand(joined)) {
                    send({ level: "crypto", message: "[Frida] Root terminal command array blocked: " + joined });
                    return this.exec(["just_a_fake_command"]);
                }
                return this.exec(cmdArray);
            };
        } catch (e) { /* overload not present on this ART version */ }

        try {
            Runtime.exec.overload("[Ljava.lang.String;", "[Ljava.lang.String;").implementation = function (cmdArray, envp) {
                const joined = cmdArray.join(" ");
                if (looksLikeRootCommand(joined)) {
                    send({ level: "crypto", message: "[Frida] Root terminal command array (with env) blocked: " + joined });
                    return this.exec(["just_a_fake_command"], envp);
                }
                return this.exec(cmdArray, envp);
            };
        } catch (e) { /* overload not present on this ART version */ }

        try {
            const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
            ProcessBuilder.start.implementation = function () {
                const cmd = this.command();
                const joined = cmd.toString();
                if (looksLikeRootCommand(joined)) {
                    send({ level: "crypto", message: "[Frida] ProcessBuilder root command blocked: " + joined });
                    this.command(Java.use("java.util.ArrayList").$new([Java.use("java.lang.String").$new("just_a_fake_command")]));
                }
                return this.start();
            };
        } catch (e) { /* ProcessBuilder not reachable/instrumentable on this target */ }

        try {
            const Build = Java.use("android.os.Build");
            if (Build.TAGS.value && Build.TAGS.value.indexOf("test-keys") > -1) {
                send({ level: "crypto", message: "[Frida] Build.TAGS spoofed from '" + Build.TAGS.value + "' to 'release-keys'" });
                Build.TAGS.value = "release-keys";
            }
        } catch (e) { /* field may be compile-time inlined on this ART build; not always overridable */ }

        send({ level: "crypto", message: "[Frida] Root evasion constraints fully activated." });
    });
}
