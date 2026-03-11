/**
 * devguard_native.cpp
 *
 * Native (C++) security detection library for DevGuard.
 * All checks use direct syscalls / C library calls to bypass JVM-layer hooks
 * (Xposed, LSPosed, Frida Java API hooking).
 *
 * JNI class: com.hajunwon.devguard.data.detector.NativeDetector
 */

#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <sys/syscall.h>

#define TAG      "DevGuard"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define CLASS    "com_hajunwon_devguard_data_detector_NativeDetector"

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

static bool path_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/** in-place ASCII lower-case */
static void str_lower(char* dst, const char* src, size_t max) {
    size_t i = 0;
    while (i < max - 1 && src[i]) { dst[i] = (char)tolower((unsigned char)src[i]); i++; }
    dst[i] = '\0';
}

// ────────────────────────────────────────────────────────────────────────────
// ROOT DETECTION
// ────────────────────────────────────────────────────────────────────────────

/**
 * stat() each known su binary path.
 * Bypasses any Java hook on File.exists() or Runtime.exec().
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckSuExists(
        JNIEnv*, jobject) {
    static const char* SU_PATHS[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/su/bin/su", "/su/xbin/su",
        "/cache/su", "/data/local/tmp/su",
        nullptr
    };
    for (int i = 0; SU_PATHS[i]; i++) {
        if (path_exists(SU_PATHS[i])) {
            LOGI("su binary: %s", SU_PATHS[i]);
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

/**
 * stat() Magisk / APatch / Zygisk indicator paths.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckMagiskFiles(
        JNIEnv*, jobject) {
    static const char* PATHS[] = {
        "/data/adb/magisk", "/data/adb/magisk.db",
        "/sbin/.magisk",    "/sbin/.core/mirror",
        "/data/adb/ap",     "/data/adb/apatch",
        "/data/adb/modules",
        "/data/adb/ksu",    "/data/adb/ksud",
        "/data/adb/ksu/bin/ksud",
        nullptr
    };
    for (int i = 0; PATHS[i]; i++) {
        if (path_exists(PATHS[i])) {
            LOGI("Magisk/APatch/KSU: %s", PATHS[i]);
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

/**
 * getuid() == 0 → process is running as root.
 * Harder to hook than Java's equivalent.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckIsRoot(
        JNIEnv*, jobject) {
    bool root = (getuid() == 0);
    if (root) LOGI("getuid() == 0 (root)");
    return root ? JNI_TRUE : JNI_FALSE;
}

/**
 * Parse /proc/self/maps in C to detect hook libraries.
 * Bypasses any Xposed hook on FileInputStream / BufferedReader.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckMapsForHooks(
        JNIEnv*, jobject) {
    static const char* PATTERNS[] = { "frida", "gadget", "substrate", "xposed", "dobby", "lsphook", "sandhook", nullptr };
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return JNI_FALSE;
    char line[512], lower[512];
    bool found = false;
    while (!found && fgets(line, sizeof(line), f)) {
        str_lower(lower, line, sizeof(lower));
        for (int i = 0; PATTERNS[i]; i++) {
            if (strstr(lower, PATTERNS[i])) {
                LOGI("maps hook: %s", line);
                found = true;
                break;
            }
        }
    }
    fclose(f);
    return found ? JNI_TRUE : JNI_FALSE;
}

/**
 * Parse /proc/self/mountinfo for Magisk/KSU overlay mounts.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckMountInfo(
        JNIEnv*, jobject) {
    static const char* KEYWORDS[] = { "magisk", "ksu", "apatch", "/data/adb", "lspatch", nullptr };
    static const char* SYS_PARTS[] = { "/system", "/vendor", "/product", nullptr };
    FILE* f = fopen("/proc/self/mountinfo", "r");
    if (!f) return JNI_FALSE;
    char line[1024], lower[1024];
    bool found = false;
    while (!found && fgets(line, sizeof(line), f)) {
        str_lower(lower, line, sizeof(lower));
        for (int i = 0; KEYWORDS[i]; i++) {
            if (strstr(lower, KEYWORDS[i])) { found = true; break; }
        }
        if (!found && strstr(lower, "overlay")) {
            for (int i = 0; SYS_PARTS[i]; i++) {
                if (strstr(lower, SYS_PARTS[i])) { found = true; break; }
            }
        }
        if (found) LOGI("mountinfo suspicious: %.120s", line);
    }
    fclose(f);
    return found ? JNI_TRUE : JNI_FALSE;
}

/** dl_iterate_phdr callback state */
struct PhdrData { bool found; };

static int phdr_hook_cb(struct dl_phdr_info* info, size_t, void* data) {
    if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
    static const char* PATTERNS[] = { "frida", "gadget", "substrate", "xposed", "lspatch", "dobby", "sandhook", nullptr };
    char lower[512];
    str_lower(lower, info->dlpi_name, sizeof(lower));
    for (int i = 0; PATTERNS[i]; i++) {
        if (strstr(lower, PATTERNS[i])) {
            LOGI("hook .so loaded: %s", info->dlpi_name);
            ((PhdrData*)data)->found = true;
            return 1; // stop
        }
    }
    return 0;
}

/**
 * Enumerate all loaded shared libraries via dl_iterate_phdr.
 * Detects Frida gadget / Substrate / Xposed even if hidden from /proc/maps.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckLoadedHookLibs(
        JNIEnv*, jobject) {
    PhdrData d = { false };
    dl_iterate_phdr(phdr_hook_cb, &d);
    return d.found ? JNI_TRUE : JNI_FALSE;
}

// ────────────────────────────────────────────────────────────────────────────
// DEBUG / HOOKING DETECTION
// ────────────────────────────────────────────────────────────────────────────

/**
 * ptrace(PTRACE_TRACEME) anti-debug check.
 *
 * If PTRACE_TRACEME returns -1 with EPERM, another process is already
 * tracing us (debugger attached). Returns true = being traced.
 *
 * If it succeeds (returns 0), we are NOT being traced.
 * The flag is set on the process but has no behavioural side-effect
 * because Android's app server is not a ptrace tracer.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckPtrace(
        JNIEnv*, jobject) {
    // PTRACE_TRACEME sets a persistent per-process flag — a second call always
    // returns EPERM even without a debugger attached. Cache the first result so
    // that re-scans do not produce false positives.
    // -1 = unchecked, 0 = not traced, 1 = traced
    static int g_ptrace_result = -1;
    if (g_ptrace_result != -1) {
        return g_ptrace_result ? JNI_TRUE : JNI_FALSE;
    }
    long r = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    if (r == -1) {
        LOGI("ptrace(PTRACE_TRACEME) failed errno=%d → being traced", errno);
        g_ptrace_result = 1;
        return JNI_TRUE;
    }
    g_ptrace_result = 0;
    return JNI_FALSE;
}

/**
 * Read TracerPid directly from /proc/self/status in C.
 * Bypasses Java file I/O hooks.
 */
extern "C" JNIEXPORT jint JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeReadTracerPid(
        JNIEnv*, jobject) {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    int pid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            pid = atoi(line + 10);
            break;
        }
    }
    fclose(f);
    if (pid != 0) LOGI("TracerPid = %d (native)", pid);
    return pid;
}

/**
 * Non-blocking TCP connect to 127.0.0.1:<port> with 50 ms timeout.
 * Bypasses Java Socket hooking by using BSD socket syscalls directly.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckFridaPort(
        JNIEnv*, jobject, jint port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return JNI_FALSE;

    // Non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    bool connected = false;
    int r = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (r == 0) {
        connected = true;
    } else if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(sock, &wset);
        struct timeval tv = { 0, 50000 }; // 50 ms
        if (select(sock + 1, nullptr, &wset, nullptr, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            connected = (err == 0);
        }
    }
    close(sock);
    if (connected) LOGI("Frida port %d open (native)", port);
    return connected ? JNI_TRUE : JNI_FALSE;
}

/**
 * Scan /proc/[pid]/cmdline for "frida" using opendir/readdir.
 * Bypasses Java-based /proc enumeration hooks.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckFridaProcess(
        JNIEnv*, jobject) {
    DIR* proc = opendir("/proc");
    if (!proc) return JNI_FALSE;
    struct dirent* ent;
    bool found = false;
    while (!found && (ent = readdir(proc)) != nullptr) {
        // Only numeric directories (PIDs)
        const char* n = ent->d_name;
        bool is_pid = (*n != '\0');
        for (const char* c = n; *c; c++) { if (*c < '0' || *c > '9') { is_pid = false; break; } }
        if (!is_pid) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%s/cmdline", n);
        FILE* f = fopen(path, "r");
        if (!f) continue;
        char buf[256];
        size_t sz = fread(buf, 1, sizeof(buf) - 1, f);
        buf[sz] = '\0';
        fclose(f);

        char lower[256];
        str_lower(lower, buf, sizeof(lower));
        if (strstr(lower, "frida")) {
            LOGI("Frida process: /proc/%s", n);
            found = true;
        }
    }
    closedir(proc);
    return found ? JNI_TRUE : JNI_FALSE;
}

// ────────────────────────────────────────────────────────────────────────────
// INTEGRITY DETECTION
// ────────────────────────────────────────────────────────────────────────────

/**
 * Read /sys/fs/selinux/enforce.
 * '0' = Permissive (insecure / rooted), '1' = Enforcing (normal).
 * Reading this file from C bypasses any SELinux status hook.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckSelinuxPermissive(
        JNIEnv*, jobject) {
    FILE* f = fopen("/sys/fs/selinux/enforce", "r");
    if (!f) return JNI_FALSE; // unreadable → assume enforcing
    char buf[4] = { 0 };
    fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    bool permissive = (buf[0] == '0');
    if (permissive) LOGI("SELinux permissive (native)");
    return permissive ? JNI_TRUE : JNI_FALSE;
}

// ────────────────────────────────────────────────────────────────────────────
// EMULATOR DETECTION
// ────────────────────────────────────────────────────────────────────────────

/**
 * __system_property_get("ro.kernel.qemu") → "1" = QEMU emulator.
 * Bypasses any Xposed hook on android.os.Build or System.getProperty.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckQemuProp(
        JNIEnv*, jobject) {
    char val[PROP_VALUE_MAX] = { 0 };
    __system_property_get("ro.kernel.qemu", val);
    bool qemu = (val[0] == '1');
    if (qemu) LOGI("ro.kernel.qemu=1 (native)");
    return qemu ? JNI_TRUE : JNI_FALSE;
}

/**
 * stat() QEMU-specific device nodes.
 * Bypasses Java File.exists() hooks.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckQemuFiles(
        JNIEnv*, jobject) {
    bool found = path_exists("/dev/qemu_pipe") || path_exists("/dev/socket/qemud");
    if (found) LOGI("QEMU device file present (native)");
    return found ? JNI_TRUE : JNI_FALSE;
}

/**
 * __system_property_get("ro.product.cpu.abi") → contains "x86" = likely emulator.
 * Bypasses Xposed hooks on Build.SUPPORTED_ABIS.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckCpuIsX86(
        JNIEnv*, jobject) {
    char abi[PROP_VALUE_MAX] = { 0 };
    __system_property_get("ro.product.cpu.abi", abi);
    char lower[PROP_VALUE_MAX];
    str_lower(lower, abi, sizeof(lower));
    bool x86 = (strstr(lower, "x86") != nullptr);
    if (x86) LOGI("CPU ABI is x86 (native): %s", abi);
    return x86 ? JNI_TRUE : JNI_FALSE;
}

// ════════════════════════════════════════════════════════════════════════════
// SYSCALL LAYER — raw kernel calls, bypasses Frida / Dobby inline hooks on libc
// ════════════════════════════════════════════════════════════════════════════

/**
 * Check file existence via syscall(SYS_faccessat).
 * Bypasses any inline hook on libc's access() / stat().
 */
static bool sc_path_exists(const char* path) {
    return syscall(SYS_faccessat, AT_FDCWD, path, F_OK, 0) == 0;
}

/**
 * Open + read + close a small file entirely via raw syscalls.
 * Returns bytes read (≥ 0) or -1 on failure. Always NUL-terminates buf.
 */
static ssize_t sc_read_file(const char* path, char* buf, size_t max) {
    long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) { buf[0] = '\0'; return -1; }
    long n = syscall(SYS_read, (int)fd, buf, max - 1);
    syscall(SYS_close, (int)fd);
    if (n > 0) { buf[n] = '\0'; return n; }
    buf[0] = '\0';
    return (n == 0) ? 0 : -1;
}

/**
 * Scan a file for any of the given lowercase patterns via raw syscall reads.
 * Reads the file in 4 KB chunks — patterns shorter than 4 KB are reliably found.
 */
static bool sc_scan_file(const char* path, const char** patterns) {
    long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return false;
    char buf[4096], lower[4096];
    bool found = false;
    ssize_t n;
    while (!found && (n = (ssize_t)syscall(SYS_read, (int)fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        str_lower(lower, buf, (size_t)(n + 1));
        for (int i = 0; patterns[i]; i++)
            if (strstr(lower, patterns[i])) { found = true; break; }
    }
    syscall(SYS_close, (int)fd);
    return found;
}

/** Kernel-level directory entry struct required by SYS_getdents64. */
struct sc_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[1]; // variable length
};

// ── Syscall: Root ────────────────────────────────────────────────────────────

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_syscallCheckSuExists(
        JNIEnv*, jobject) {
    static const char* PATHS[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/su/bin/su", "/su/xbin/su",
        "/cache/su", "/data/local/tmp/su", nullptr
    };
    for (int i = 0; PATHS[i]; i++)
        if (sc_path_exists(PATHS[i])) { LOGI("[syscall] su: %s", PATHS[i]); return JNI_TRUE; }
    return JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_syscallCheckMagiskFiles(
        JNIEnv*, jobject) {
    static const char* PATHS[] = {
        "/data/adb/magisk", "/data/adb/magisk.db",
        "/sbin/.magisk",    "/sbin/.core/mirror",
        "/data/adb/ap",     "/data/adb/apatch",
        "/data/adb/modules",
        "/data/adb/ksu",    "/data/adb/ksud",
        "/data/adb/ksu/bin/ksud", nullptr
    };
    for (int i = 0; PATHS[i]; i++)
        if (sc_path_exists(PATHS[i])) { LOGI("[syscall] magisk/ksu: %s", PATHS[i]); return JNI_TRUE; }
    return JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_syscallCheckIsRoot(
        JNIEnv*, jobject) {
    bool root = (syscall(SYS_getuid) == 0);
    if (root) LOGI("[syscall] getuid() == 0 (root)");
    return root ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_syscallCheckMapsForHooks(
        JNIEnv*, jobject) {
    static const char* P[] = { "frida", "gadget", "substrate", "xposed", "dobby", "lsphook", "sandhook", nullptr };
    bool found = sc_scan_file("/proc/self/maps", P);
    if (found) LOGI("[syscall] hook found in /proc/self/maps");
    return found ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_syscallCheckMountInfo(
        JNIEnv*, jobject) {
    static const char* P[] = { "magisk", "ksu", "apatch", "/data/adb", "lspatch", nullptr };
    bool found = sc_scan_file("/proc/self/mountinfo", P);
    if (found) LOGI("[syscall] suspicious mount in mountinfo");
    return found ? JNI_TRUE : JNI_FALSE;
}

// ── Syscall: Debug ───────────────────────────────────────────────────────────

extern "C" JNIEXPORT jint JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_syscallReadTracerPid(
        JNIEnv*, jobject) {
    char buf[4096] = {};
    if (sc_read_file("/proc/self/status", buf, sizeof(buf)) <= 0) return 0;
    const char* p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    int pid = atoi(p + 10);
    if (pid != 0) LOGI("[syscall] TracerPid = %d", pid);
    return pid;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_syscallCheckFridaProcess(
        JNIEnv*, jobject) {
    long dfd = syscall(SYS_openat, AT_FDCWD, "/proc", O_RDONLY | O_DIRECTORY, 0);
    if (dfd < 0) return JNI_FALSE;
    char buf[2048];
    bool found = false;
    while (!found) {
        long n = syscall(SYS_getdents64, (int)dfd, buf, sizeof(buf));
        if (n <= 0) break;
        for (long pos = 0; pos < n; ) {
            sc_dirent64* de = reinterpret_cast<sc_dirent64*>(buf + pos);
            if (de->d_reclen == 0) break;
            pos += de->d_reclen;
            const char* name = de->d_name;
            bool is_pid = (*name != '\0');
            for (const char* c = name; *c; c++) {
                if (*c < '0' || *c > '9') { is_pid = false; break; }
            }
            if (!is_pid) continue;
            char path[64];
            snprintf(path, sizeof(path), "/proc/%s/cmdline", name);
            char cmd[256] = {}, lower[256] = {};
            if (sc_read_file(path, cmd, sizeof(cmd)) > 0) {
                str_lower(lower, cmd, sizeof(lower));
                if (strstr(lower, "frida")) {
                    LOGI("[syscall] Frida process: /proc/%s", name);
                    found = true; break;
                }
            }
        }
    }
    syscall(SYS_close, (int)dfd);
    return found ? JNI_TRUE : JNI_FALSE;
}

// ── Syscall: Integrity ───────────────────────────────────────────────────────

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_syscallCheckSelinuxPermissive(
        JNIEnv*, jobject) {
    char buf[4] = {};
    if (sc_read_file("/sys/fs/selinux/enforce", buf, sizeof(buf)) < 0) return JNI_FALSE;
    bool permissive = (buf[0] == '0');
    if (permissive) LOGI("[syscall] SELinux permissive");
    return permissive ? JNI_TRUE : JNI_FALSE;
}

// ── Syscall: Emulator ────────────────────────────────────────────────────────

extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_syscallCheckQemuFiles(
        JNIEnv*, jobject) {
    bool found = sc_path_exists("/dev/qemu_pipe") || sc_path_exists("/dev/socket/qemud");
    if (found) LOGI("[syscall] QEMU device file present");
    return found ? JNI_TRUE : JNI_FALSE;
}

// ════════════════════════════════════════════════════════════════════════════
// JNI LAYER: libc inline hook detection (Dobby / Frida NativeHook)
// ════════════════════════════════════════════════════════════════════════════

/**
 * Inspect the first instruction of a function pointer for trampoline patterns.
 *
 * arm64  — Dobby patches: LDR Xn, #8; BR Xn   → first word is 0x58xxxxxx
 * x86_64 — Frida patches: JMP rel32 (0xE9) or JMP [RIP+disp] (0xFF 0x25)
 *
 * Returns true if a hook is suspected.
 */
static bool sc_is_hooked(void* fn) {
    if (!fn) return false;
#if defined(__aarch64__)
    uint32_t first; __builtin_memcpy(&first, fn, 4);
    if ((first & 0xFF000000u) == 0x58000000u) return true; // LDR Xn, literal
    if ((first & 0xFC000000u) == 0x14000000u) return true; // B  <offset>
    if ((first & 0xFC000000u) == 0x94000000u) return true; // BL <offset>
    return false;
#elif defined(__x86_64__) || defined(__i386__)
    const uint8_t* b = (const uint8_t*)fn;
    if (b[0] == 0xE9)                         return true; // JMP rel32
    if (b[0] == 0xFF && b[1] == 0x25)         return true; // JMP [RIP+disp32]
    if (b[0] == 0x49 && b[1] == 0xBB)         return true; // MOV R11, imm64
    return false;
#else
    (void)fn; return false;
#endif
}

/**
 * Check if commonly-hooked libc functions have been inline-patched.
 * Specifically includes fgets — the confirmed Dobby hook target for this app.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_hajunwon_devguard_data_detector_NativeDetector_nativeCheckLibcHooked(
        JNIEnv*, jobject) {
    static const char* TARGETS[] = {
        "fgets", "fopen", "fread", "opendir", "readdir", "access", "stat",
        "getuid", "open",   // hooked by root-hiders to spoof UID / hide file paths
        nullptr
    };
    for (int i = 0; TARGETS[i]; i++) {
        void* sym = dlsym(RTLD_DEFAULT, TARGETS[i]);
        if (sym && sc_is_hooked(sym)) {
            LOGI("[JNI] libc hook on: %s", TARGETS[i]);
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}
