package com.hajunwon.devguard.data.detector

/**
 * JNI bridge to the native security detection library (devguard_native.so).
 *
 * Three detection layers:
 *   JNI (native*)     — C++ via libc calls; bypasses Java/Xposed hooks.
 *   SYSCALL (syscall*) — raw kernel syscall(); bypasses Frida/Dobby libc hooks.
 *   Hook detection     — checks if libc function prologues are inline-patched.
 *
 * Graceful fallback: if the native library fails to load (e.g. unsupported ABI),
 * [isAvailable] is set to false and callers should skip all native signals.
 */
object NativeDetector {

    var isAvailable: Boolean = false
        private set

    init {
        try {
            System.loadLibrary("devguard_native")
            isAvailable = true
        } catch (_: UnsatisfiedLinkError) {
            isAvailable = false
        }
    }

    // ── Root ─────────────────────────────────────────────────────────────────

    /** stat() su binary paths — bypasses Java File.exists() hooks */
    external fun nativeCheckSuExists(): Boolean

    /** stat() Magisk / APatch / Zygisk indicator paths */
    external fun nativeCheckMagiskFiles(): Boolean

    /** getuid() == 0 */
    external fun nativeCheckIsRoot(): Boolean

    /** C fopen(/proc/self/maps) scan for frida/gadget/substrate/xposed */
    external fun nativeCheckMapsForHooks(): Boolean

    /** C fopen(/proc/self/mountinfo) scan for overlay/magisk/ksu mounts */
    external fun nativeCheckMountInfo(): Boolean

    /** dl_iterate_phdr() enumeration of all loaded .so files */
    external fun nativeCheckLoadedHookLibs(): Boolean

    // ── Debug / Hooking ───────────────────────────────────────────────────────

    /** ptrace(PTRACE_TRACEME) — returns true if EPERM (already being traced) */
    external fun nativeCheckPtrace(): Boolean

    /** C fopen(/proc/self/status) TracerPid read */
    external fun nativeReadTracerPid(): Int

    /** Non-blocking C socket connect to 127.0.0.1:<port> with 50 ms timeout */
    external fun nativeCheckFridaPort(port: Int): Boolean

    /** opendir/readdir /proc scan for frida in process cmdline */
    external fun nativeCheckFridaProcess(): Boolean

    // ── Integrity ─────────────────────────────────────────────────────────────

    /** C fopen(/sys/fs/selinux/enforce) — '0' = permissive */
    external fun nativeCheckSelinuxPermissive(): Boolean

    // ── Emulator ──────────────────────────────────────────────────────────────

    /** __system_property_get("ro.kernel.qemu") == "1" */
    external fun nativeCheckQemuProp(): Boolean

    /** stat() /dev/qemu_pipe and /dev/socket/qemud */
    external fun nativeCheckQemuFiles(): Boolean

    /** __system_property_get("ro.product.cpu.abi") contains "x86" */
    external fun nativeCheckCpuIsX86(): Boolean

    // ── Syscall layer ─────────────────────────────────────────────────────────
    // Uses syscall() directly — bypasses Frida / Dobby inline hooks on libc.

    /** syscall(SYS_faccessat) su binary paths */
    external fun syscallCheckSuExists(): Boolean

    /** syscall(SYS_faccessat) Magisk / APatch / Zygisk paths */
    external fun syscallCheckMagiskFiles(): Boolean

    /** syscall(SYS_getuid) == 0 */
    external fun syscallCheckIsRoot(): Boolean

    /** syscall(SYS_openat/read/close) scan /proc/self/maps */
    external fun syscallCheckMapsForHooks(): Boolean

    /** syscall(SYS_openat/read/close) scan /proc/self/mountinfo */
    external fun syscallCheckMountInfo(): Boolean

    /** syscall(SYS_openat/read/close) TracerPid from /proc/self/status */
    external fun syscallReadTracerPid(): Int

    /** syscall(SYS_openat + SYS_getdents64) scan /proc for Frida */
    external fun syscallCheckFridaProcess(): Boolean

    /** syscall(SYS_openat/read/close) read /sys/fs/selinux/enforce */
    external fun syscallCheckSelinuxPermissive(): Boolean

    /** syscall(SYS_faccessat) /dev/qemu_pipe and /dev/socket/qemud */
    external fun syscallCheckQemuFiles(): Boolean

    // ── JNI: libc inline hook detection ──────────────────────────────────────

    /** Inspect fopen/fgets/stat/opendir/access prologues for Dobby/Frida inline patches */
    external fun nativeCheckLibcHooked(): Boolean
}
