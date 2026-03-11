package com.hajunwon.devguard.data.detector

import android.os.Build
import com.hajunwon.devguard.data.model.DetectorResult
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import com.hajunwon.devguard.data.model.SignalLayer
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

object RootDetector {

    // Magisk/KSU/APatch paths kept separate from su binary paths to avoid double-counting
    private val suPaths = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/su/bin/su", "/su/xbin/su",
        "/cache/su", "/data/local/tmp/su",
    )
    private val bbPaths = listOf(
        "/system/bin/busybox", "/system/xbin/busybox", "/sbin/busybox",
        "/data/adb/magisk/busybox"
    )
    private val xposedPaths = listOf(
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/data/adb/lspatch"
    )
    private val magiskPaths = listOf(
        "/data/adb/magisk", "/data/adb/magisk.db",
        "/sbin/.magisk", "/sbin/.core/mirror", "/sbin/.core/img"
    )
    private val apatchPaths = listOf(
        "/data/adb/ap", "/data/adb/apatch"
    )
    private val ksuPaths = listOf(
        "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ksu/bin/ksud",
        "/data/adb/ksu/bin/busybox",
        "/data/adb/modules/kernelsu",
    )
    private val riruPaths = listOf(
        "/data/adb/riru", "/data/misc/riru/api"
    )
    // Shamiko hides Magisk/DenyList from apps — detected even without Magisk files visible
    private val shamikoPaths = listOf(
        "/data/adb/modules/zygisk_shamiko",
        "/data/adb/modules/shamiko"
    )
    private val substratePaths = listOf(
        "/system/lib/libsubstrate.so",
        "/system/lib64/libsubstrate.so"
    )

    private fun checkZygiskModules(): Boolean = try {
        val dir = File("/data/adb/modules")
        dir.exists() && dir.isDirectory && dir.listFiles()?.isNotEmpty() == true
    } catch (e: Exception) { false }

    /**
     * Checks /proc/self/maps for .so files loaded from world-writable staging areas.
     * Frida Gadget (even when renamed) is typically placed in /data/local/tmp/
     * or external storage before injection. Legitimate libraries load from
     * /system/, /apex/, /vendor/, /data/app/ — never from staging paths.
     */
    private fun checkSuspiciousInjectedSo(mapsContent: String): Boolean {
        val suspiciousLocations = listOf(
            "/data/local/tmp/",     // world-writable: primary frida-server / gadget staging area
            "/sdcard/",             // external storage
            "/storage/emulated/",   // external storage (Android 6+)
            "/mnt/sdcard/",         // external storage (legacy)
        )
        return mapsContent.lines()
            .filter { it.contains(".so") }
            .any { line ->
                val path = line.substringAfterLast(" ").trim()
                path.endsWith(".so") && suspiciousLocations.any { path.startsWith(it) }
            }
    }

    /**
     * Checks if Xposed/LSPosed is loaded into this process by attempting to load
     * XposedBridge via the app's own classloader — harder to hook than Class.forName().
     */
    private fun checkXposedLoaded(): Boolean = try {
        val cl = RootDetector::class.java.classLoader!!
        val xposedClasses = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers",
        )
        xposedClasses.any { name ->
            try { cl.loadClass(name); true } catch (e: ClassNotFoundException) { false }
        }
    } catch (e: Exception) { false }

    /**
     * Checks /proc/self/mountinfo for overlay mounts on system partitions (Magisk)
     * and suspicious keywords (KernelSU, APatch, etc.).
     */
    private fun checkSuspiciousMounts(): Boolean = try {
        val mountinfo = File("/proc/self/mountinfo").readText()
        val lines = mountinfo.lines()

        // overlayfs on /system, /vendor, /product → Magisk magic mount
        val overlayOnSystem = lines.any { line ->
            val parts = line.split(" ")
            val mountPoint = parts.getOrNull(4) ?: ""
            val separatorIdx = parts.indexOf("-")
            val fsType = if (separatorIdx >= 0) parts.getOrNull(separatorIdx + 1) ?: "" else ""
            fsType == "overlay" && listOf("/system", "/vendor", "/product").any {
                mountPoint.startsWith(it)
            }
        }

        val suspiciousKeywords = listOf("magisk", "ksu", "apatch", "/data/adb", "lspatch")
        val hasSuspiciousKeyword = suspiciousKeywords.any {
            mountinfo.contains(it, ignoreCase = true)
        }

        overlayOnSystem || hasSuspiciousKeyword
    } catch (e: Exception) { false }

    /**
     * Executes `su -c id`. If an Xposed hook intercepts and throws IOException,
     * the exception stack trace will contain Xposed frames — we flip that to a positive signal.
     */
    private fun checkSuExecution(): Boolean = try {
        val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
        val finished = process.waitFor(300, TimeUnit.MILLISECONDS)
        if (finished) process.exitValue() == 0 else { process.destroy(); false }
    } catch (e: IOException) {
        // Hook threw IOException to fake "su not found" — Xposed frames will be in the stack
        e.stackTrace.any {
            it.className.contains("xposed", ignoreCase = true) ||
            it.className.contains("LSPHooker", ignoreCase = true)
        }
    } catch (e: Exception) { false }

    /** Extracts the value from a getprop line like "[ro.boot.foo]: [bar]" */
    private fun extractProp(props: String, key: String): String =
        props.lines()
            .firstOrNull { it.contains("[$key]") }
            ?.let { Regex("""\[([^\]]*)]$""").find(it.trim())?.groupValues?.getOrNull(1) }
            ?: ""

    fun scan(props: String): DetectorResult {
        // Check each path group once — reuse results in both signals and rawData
        val suStatus        = suPaths.associateWith { File(it).exists() }
        val bbStatus        = bbPaths.associateWith { File(it).exists() }
        val xposedStatus    = xposedPaths.associateWith { File(it).exists() }
        val magiskStatus    = magiskPaths.associateWith { File(it).exists() }
        val apatchStatus    = apatchPaths.associateWith { File(it).exists() }
        val ksuStatus       = ksuPaths.associateWith { File(it).exists() }
        val riruStatus      = riruPaths.associateWith { File(it).exists() }
        val shamikoStatus   = shamikoPaths.associateWith { File(it).exists() }
        val substrateStatus = substratePaths.associateWith { File(it).exists() }

        val suFound      = suStatus.values.any { it }
        val bbFound      = bbStatus.values.any { it }
        val debuggable   = props.contains("ro.debuggable]: [1]")
        val secureOff    = props.contains("ro.secure]: [0]")

        // Bootloader unlock indicators — still visible even with Sulist/DenyList because
        // these are kernel-sourced properties that Magisk does not resetprop by default.
        val verifiedBootState  = extractProp(props, "ro.boot.verifiedbootstate")
        val flashLocked        = extractProp(props, "ro.boot.flash.locked")
        // "green" = locked + AVB pass; "yellow"/"orange" = unlocked; "" = prop absent (older devices)
        val bootloaderUnlocked = verifiedBootState.isNotEmpty() && verifiedBootState != "green"
        val flashUnlocked      = flashLocked == "0"
        val superuser    = File("/system/app/Superuser.apk").exists()
        val testKeys     = Build.TAGS.contains("test-keys", true)
        val devBuildType = Build.TYPE == "userdebug" || Build.TYPE == "eng"
        val xposed       = xposedStatus.values.any { it }
        val magisk       = magiskStatus.values.any { it }
        val apatch       = apatchStatus.values.any { it }
        val ksu          = ksuStatus.values.any { it }
        val riru         = riruStatus.values.any { it }
        val shamiko      = shamikoStatus.values.any { it }
        val substrate    = substrateStatus.values.any { it }
        val zygisk       = checkZygiskModules()
        // service.adb.root=1 means adb was granted root shell — survives most root hiders
        val adbrootProp  = props.contains("service.adb.root]: [1]")

        // Read /proc/self/maps once — reuse for both detection and rawData display
        val mapsContent = try { File("/proc/self/maps").readText() } catch (e: Exception) { "" }
        // Expanded keyword set: dobby (inline hook), lsphook/edxposed/sandhook (Xposed forks)
        val memMaps     = listOf("frida", "gadget", "substrate", "xposed", "dobby", "lsphook", "edxposed", "sandhook").any {
            mapsContent.contains(it, ignoreCase = true)
        }
        // Detect generic hook/inject .so names loaded from APK data dirs (e.g. libdevicer_hook.so)
        val hookSoName  = mapsContent.lines()
            .filter { it.contains(".so") }
            .any { line ->
                val soName = line.substringAfterLast("/").lowercase()
                soName.contains("hook") || soName.contains("inject") || soName.contains("patch")
            }
        val xposedLoaded     = checkXposedLoaded()
        val suspiciousMounts = checkSuspiciousMounts()
        val suExec           = checkSuExecution()

        // ── JNI layer results ────────────────────────────────────────────────
        val nativeSuExists  = NativeDetector.isAvailable && NativeDetector.nativeCheckSuExists()
        val nativeMagisk    = NativeDetector.isAvailable && NativeDetector.nativeCheckMagiskFiles()
        val nativeIsRoot    = NativeDetector.isAvailable && NativeDetector.nativeCheckIsRoot()
        val nativeMapsHooks = NativeDetector.isAvailable && NativeDetector.nativeCheckMapsForHooks()
        val nativeMount     = NativeDetector.isAvailable && NativeDetector.nativeCheckMountInfo()
        val nativeHookLibs  = NativeDetector.isAvailable && NativeDetector.nativeCheckLoadedHookLibs()
        val libcHooked      = NativeDetector.isAvailable && NativeDetector.nativeCheckLibcHooked()

        // ── Syscall layer results ────────────────────────────────────────────
        val syscallSuExists  = NativeDetector.isAvailable && NativeDetector.syscallCheckSuExists()
        val syscallMagisk    = NativeDetector.isAvailable && NativeDetector.syscallCheckMagiskFiles()
        val syscallIsRoot    = NativeDetector.isAvailable && NativeDetector.syscallCheckIsRoot()
        val syscallMapsHooks = NativeDetector.isAvailable && NativeDetector.syscallCheckMapsForHooks()
        val syscallMount     = NativeDetector.isAvailable && NativeDetector.syscallCheckMountInfo()

        // ── Java / JNI discrepancy ────────────────────────────────────────────
        // Java says "clean" but JNI finds root → DenyList hiding files from Java FS layer.
        val javaSaysSafeFromRoot = !suFound && !magisk && !ksu && !apatch
        val jniFindsRoot         = nativeSuExists || nativeMagisk || nativeIsRoot
        val layerMismatch        = NativeDetector.isAvailable && javaSaysSafeFromRoot && jniFindsRoot

        // ── JNI / Syscall discrepancy ─────────────────────────────────────────
        // JNI says "clean" but Syscall finds root → Frida/Dobby hooked libc stat()/access()
        // to hide evidence from the JNI layer too.
        val jniSaysSafeFromRoot = !nativeSuExists && !nativeMagisk && !nativeIsRoot
        val syscallFindsRoot    = syscallSuExists || syscallMagisk || syscallIsRoot
        val jniSyscallMismatch  = NativeDetector.isAvailable && jniSaysSafeFromRoot && syscallFindsRoot

        // ── Injected .so from staging path ───────────────────────────────────
        val suspiciousSo = checkSuspiciousInjectedSo(mapsContent)

        val jvmSignals = listOf(
            Signal(SignalCategory.ROOT, "su binary found",                          "su binary not found",                   3, suFound,           group = "root_su"),
            Signal(SignalCategory.ROOT, "busybox found",                            "busybox not found",                     2, bbFound),
            Signal(SignalCategory.ROOT, "ro.debuggable = 1 (rooted)",              "ro.debuggable = 0 (normal)",            3, debuggable),
            Signal(SignalCategory.ROOT, "ro.secure = 0 (rooted)",                  "ro.secure = 1 (normal)",                3, secureOff),
            // Bootloader unlock — survives Sulist/DenyList because it's a kernel prop not hidden by Magisk
            Signal(SignalCategory.ROOT, "Bootloader unlocked (verifiedbootstate=$verifiedBootState)", "Verified boot: green (bootloader locked)", 2, bootloaderUnlocked),
            Signal(SignalCategory.ROOT, "Bootloader unlocked (ro.boot.flash.locked=0)",               "Bootloader locked (flash.locked=1)",       2, flashUnlocked),
            Signal(SignalCategory.ROOT, "Superuser.apk found",                     "Superuser.apk not found",               3, superuser),
            Signal(SignalCategory.ROOT, "Build TAGS: test-keys",                   "Build TAGS: release-keys",              2, testKeys),
            Signal(SignalCategory.ROOT, "Build.TYPE is userdebug / eng",           "Build.TYPE is user",                    2, devBuildType),
            Signal(SignalCategory.ROOT, "Xposed / LSPosed framework found",        "Xposed not detected",                   4, xposed),
            Signal(SignalCategory.ROOT, "Magisk files found",                      "Magisk not detected",                   4, magisk),
            Signal(SignalCategory.ROOT, "APatch files found",                      "APatch not detected",                   4, apatch),
            Signal(SignalCategory.ROOT, "KernelSU files found",                   "KernelSU not detected",                 4, ksu),
            Signal(SignalCategory.ROOT, "Riru framework files found",             "Riru not detected",                     3, riru),
            Signal(SignalCategory.ROOT, "Shamiko (DenyList bypass) module found", "Shamiko not detected",                  4, shamiko),
            Signal(SignalCategory.ROOT, "Cydia Substrate SO found",               "Substrate not found",                   3, substrate),
            Signal(SignalCategory.ROOT, "Zygisk modules directory exists",        "No Zygisk modules",                     3, zygisk),
            Signal(SignalCategory.ROOT, "Frida / Substrate in /proc/self/maps",   "No hook library in memory maps",        4, memMaps,           group = "root_maps"),
            Signal(SignalCategory.ROOT, "Xposed/LSPosed active in classloader",   "No Xposed in classloader",              4, xposedLoaded),
            Signal(SignalCategory.ROOT, "Suspicious overlay mounts detected",     "No suspicious mounts",                  3, suspiciousMounts,  group = "root_mounts"),
            Signal(SignalCategory.ROOT, "su command executes successfully",        "su command blocked",                    4, suExec),
            Signal(SignalCategory.ROOT, "[Mismatch] Java/JNI: active file hiding",   "Java/JNI results consistent",           5, layerMismatch),
            Signal(SignalCategory.ROOT, ".so loaded from staging path",             "No .so in staging paths",               4, suspiciousSo),
            Signal(SignalCategory.ROOT, "Hook/inject .so loaded (name pattern)",    "No hook .so name detected",             4, hookSoName),
            Signal(SignalCategory.ROOT, "service.adb.root = 1 (ADB root active)",  "service.adb.root = 0 (normal)",         3, adbrootProp),
        )

        val jniSignals: List<Signal> = if (NativeDetector.isAvailable) listOf(
            Signal(SignalCategory.ROOT, "su binary found (stat)",           "su not found",                    3, nativeSuExists,  SignalLayer.JNI,     "root_su"),
            Signal(SignalCategory.ROOT, "Magisk/APatch/KSU files (stat)",    "No root framework files",         4, nativeMagisk,    SignalLayer.JNI,     "root_fw_native"),
            Signal(SignalCategory.ROOT, "Process running as root (getuid)", "Not running as root",             4, nativeIsRoot,    SignalLayer.JNI,     "root_uid"),
            Signal(SignalCategory.ROOT, "Hook lib in /proc/maps",           "No hook in maps",                 4, nativeMapsHooks, SignalLayer.JNI,     "root_maps"),
            Signal(SignalCategory.ROOT, "Suspicious overlay mounts",        "No suspicious mounts",            3, nativeMount,     SignalLayer.JNI,     "root_mounts"),
            Signal(SignalCategory.ROOT, "Hook .so loaded (phdr scan)",      "No hook .so loaded",              4, nativeHookLibs,  SignalLayer.JNI),
            Signal(SignalCategory.ROOT, "libc functions inline-patched",    "libc prologues intact",           5, libcHooked,      SignalLayer.JNI),
        ) else emptyList()

        val syscallSignals: List<Signal> = if (NativeDetector.isAvailable) listOf(
            Signal(SignalCategory.ROOT, "su binary (faccessat)",            "su not found",                    3, syscallSuExists,    SignalLayer.SYSCALL, "root_su"),
            Signal(SignalCategory.ROOT, "Magisk/APatch/KSU (faccessat)",    "No root framework files",         4, syscallMagisk,      SignalLayer.SYSCALL, "root_fw_native"),
            Signal(SignalCategory.ROOT, "Root uid (getuid syscall)",        "Not root",                        4, syscallIsRoot,      SignalLayer.SYSCALL, "root_uid"),
            Signal(SignalCategory.ROOT, "Hook lib in /proc/maps",           "No hook in maps",                 4, syscallMapsHooks,   SignalLayer.SYSCALL, "root_maps"),
            Signal(SignalCategory.ROOT, "Suspicious mounts",                "No suspicious mounts",            3, syscallMount,       SignalLayer.SYSCALL, "root_mounts"),
            Signal(SignalCategory.ROOT, "[Mismatch] JNI/Syscall: libc hook hides root", "JNI/Syscall consistent", 5, jniSyscallMismatch, SignalLayer.SYSCALL),
        ) else emptyList()

        val signals = jvmSignals + jniSignals + syscallSignals

        // Build rawData using cached status maps — no re-checking files
        fun Map<String, Boolean>.toRaw() =
            entries.joinToString("\n") { "${it.key} : ${if (it.value) "EXISTS" else "not found"}" }

        val fileResults      = (suStatus + mapOf("/system/app/Superuser.apk" to superuser) + bbStatus).toRaw()
        val debuggableLine   = props.lines().firstOrNull { it.contains("[ro.debuggable]") }?.trim() ?: "[ro.debuggable]: (not found)"
        val secureLine       = props.lines().firstOrNull { it.contains("[ro.secure]") }?.trim()     ?: "[ro.secure]: (not found)"
        val xposedStr        = xposedStatus.toRaw()
        val magiskStr        = magiskStatus.toRaw()
        val apatchStr        = apatchStatus.toRaw()
        val ksuStr           = ksuStatus.toRaw()
        val riruStr          = riruStatus.toRaw()
        val shamikoStr       = shamikoStatus.toRaw()
        val substrateStr     = substrateStatus.toRaw()
        val zygiskLine       = "/data/adb/modules : ${if (zygisk) "EXISTS (has modules)" else "not found / empty"}"
        val mapsHits         = mapsContent.lines()
            .filter { line -> listOf("frida", "gadget", "substrate", "xposed", "dobby", "lsphook", "edxposed", "sandhook", "hook", "inject").any { line.contains(it, true) } }
            .joinToString("\n").ifEmpty { "(nothing suspicious)" }
        val mountHits        = try {
            File("/proc/self/mountinfo").readLines()
                .filter { line -> listOf("overlay", "magisk", "ksu", "apatch", "/data/adb").any { line.contains(it, true) } }
                .joinToString("\n").ifEmpty { "(nothing suspicious)" }
        } catch (e: Exception) { "unavailable" }

        val rawData = "=== Root / SU Files ===\n$fileResults\n\n" +
               "=== Xposed Files ===\n$xposedStr\n\n" +
               "=== Magisk Files ===\n$magiskStr\n\n" +
               "=== APatch Files ===\n$apatchStr\n\n" +
               "=== KernelSU Files ===\n$ksuStr\n\n" +
               "=== Riru Files ===\n$riruStr\n\n" +
               "=== Shamiko Files ===\n$shamikoStr\n\n" +
               "=== Substrate Files ===\n$substrateStr\n\n" +
               "=== Zygisk Modules ===\n$zygiskLine\n\n" +
               "=== System Props ===\n$debuggableLine\n$secureLine\n" +
               "TAGS: ${Build.TAGS}  TYPE: ${Build.TYPE}\n" +
               "ro.boot.verifiedbootstate: ${verifiedBootState.ifEmpty { "(not found)" }}\n" +
               "ro.boot.flash.locked: ${flashLocked.ifEmpty { "(not found)" }}\n" +
               "service.adb.root: ${if (adbrootProp) "1 (ADB root active)" else "0 / not found"}\n\n" +
               "=== Xposed in Classloader ===\n${if (xposedLoaded) "DETECTED" else "not found"}\n\n" +
               "=== /proc/self/mountinfo (suspicious lines) ===\n$mountHits\n\n" +
               "=== /proc/self/maps (hook-related lines) ===\n$mapsHits\n\n" +
               "=== Hook .so name pattern ===\n${if (hookSoName) "DETECTED (hook/inject/patch in .so name)" else "not detected"}"

        return DetectorResult(signals, rawData)
    }
}
