package com.hajunwon.devguard.data.detector

import android.os.Build
import com.hajunwon.devguard.data.model.DetectorResult
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
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
    private val substratePaths = listOf(
        "/system/lib/libsubstrate.so",
        "/system/lib64/libsubstrate.so"
    )

    private fun checkZygiskModules(): Boolean = try {
        val dir = File("/data/adb/modules")
        dir.exists() && dir.isDirectory && dir.listFiles()?.isNotEmpty() == true
    } catch (e: Exception) { false }

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

    fun scan(props: String): DetectorResult {
        // Check each path group once — reuse results in both signals and rawData
        val suStatus        = suPaths.associateWith { File(it).exists() }
        val bbStatus        = bbPaths.associateWith { File(it).exists() }
        val xposedStatus    = xposedPaths.associateWith { File(it).exists() }
        val magiskStatus    = magiskPaths.associateWith { File(it).exists() }
        val apatchStatus    = apatchPaths.associateWith { File(it).exists() }
        val substrateStatus = substratePaths.associateWith { File(it).exists() }

        val suFound      = suStatus.values.any { it }
        val bbFound      = bbStatus.values.any { it }
        val debuggable   = props.contains("ro.debuggable]: [1]")
        val secureOff    = props.contains("ro.secure]: [0]")
        val superuser    = File("/system/app/Superuser.apk").exists()
        val testKeys     = Build.TAGS.contains("test-keys", true)
        val devBuildType = Build.TYPE == "userdebug" || Build.TYPE == "eng"
        val xposed       = xposedStatus.values.any { it }
        val magisk       = magiskStatus.values.any { it }
        val apatch       = apatchStatus.values.any { it }
        val substrate    = substrateStatus.values.any { it }
        val zygisk       = checkZygiskModules()

        // Read /proc/self/maps once — reuse for both detection and rawData display
        val mapsContent = try { File("/proc/self/maps").readText() } catch (e: Exception) { "" }
        val memMaps     = listOf("frida", "gadget", "substrate", "xposed").any {
            mapsContent.contains(it, ignoreCase = true)
        }
        val xposedLoaded    = checkXposedLoaded()
        val suspiciousMounts = checkSuspiciousMounts()
        val suExec          = checkSuExecution()

        val signals = listOf(
            Signal(SignalCategory.ROOT, "su binary found",                          "su binary not found",                   3, suFound),
            Signal(SignalCategory.ROOT, "busybox found",                            "busybox not found",                     2, bbFound),
            Signal(SignalCategory.ROOT, "ro.debuggable = 1 (rooted)",              "ro.debuggable = 0 (normal)",            3, debuggable),
            Signal(SignalCategory.ROOT, "ro.secure = 0 (rooted)",                  "ro.secure = 1 (normal)",                3, secureOff),
            Signal(SignalCategory.ROOT, "Superuser.apk found",                     "Superuser.apk not found",               3, superuser),
            Signal(SignalCategory.ROOT, "Build TAGS: test-keys",                   "Build TAGS: release-keys",              2, testKeys),
            Signal(SignalCategory.ROOT, "Build.TYPE is userdebug / eng",           "Build.TYPE is user",                    2, devBuildType),
            Signal(SignalCategory.ROOT, "Xposed / LSPosed framework found",        "Xposed not detected",                   4, xposed),
            Signal(SignalCategory.ROOT, "Magisk files found",                      "Magisk not detected",                   4, magisk),
            Signal(SignalCategory.ROOT, "APatch files found",                      "APatch not detected",                   4, apatch),
            Signal(SignalCategory.ROOT, "Cydia Substrate SO found",               "Substrate not found",                   3, substrate),
            Signal(SignalCategory.ROOT, "Zygisk modules directory exists",        "No Zygisk modules",                     3, zygisk),
            Signal(SignalCategory.ROOT, "Frida / Substrate in /proc/self/maps",   "No hook library in memory maps",        4, memMaps),
            Signal(SignalCategory.ROOT, "Xposed/LSPosed active in classloader",   "No Xposed in classloader",              4, xposedLoaded),
            Signal(SignalCategory.ROOT, "Suspicious overlay mounts detected",     "No suspicious mounts",                  3, suspiciousMounts),
            Signal(SignalCategory.ROOT, "su command executes successfully",        "su command blocked",                    4, suExec),
        )

        // Build rawData using cached status maps — no re-checking files
        fun Map<String, Boolean>.toRaw() =
            entries.joinToString("\n") { "${it.key} : ${if (it.value) "EXISTS" else "not found"}" }

        val fileResults      = (suStatus + mapOf("/system/app/Superuser.apk" to superuser) + bbStatus).toRaw()
        val debuggableLine   = props.lines().firstOrNull { it.contains("[ro.debuggable]") }?.trim() ?: "[ro.debuggable]: (not found)"
        val secureLine       = props.lines().firstOrNull { it.contains("[ro.secure]") }?.trim()     ?: "[ro.secure]: (not found)"
        val xposedStr        = xposedStatus.toRaw()
        val magiskStr        = magiskStatus.toRaw()
        val apatchStr        = apatchStatus.toRaw()
        val substrateStr     = substrateStatus.toRaw()
        val zygiskLine       = "/data/adb/modules : ${if (zygisk) "EXISTS (has modules)" else "not found / empty"}"
        val mapsHits         = mapsContent.lines()
            .filter { line -> listOf("frida", "gadget", "substrate", "xposed").any { line.contains(it, true) } }
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
               "=== Substrate Files ===\n$substrateStr\n\n" +
               "=== Zygisk Modules ===\n$zygiskLine\n\n" +
               "=== System Props ===\n$debuggableLine\n$secureLine\n" +
               "TAGS: ${Build.TAGS}  TYPE: ${Build.TYPE}\n\n" +
               "=== Xposed in Classloader ===\n${if (xposedLoaded) "DETECTED" else "not found"}\n\n" +
               "=== /proc/self/mountinfo (suspicious lines) ===\n$mountHits\n\n" +
               "=== /proc/self/maps (hook-related lines) ===\n$mapsHits"

        return DetectorResult(signals, rawData)
    }
}
