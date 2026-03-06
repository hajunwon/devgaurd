package com.hajunwon.devguard.data.detector

import android.os.Build
import com.hajunwon.devguard.data.model.DetectorResult
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import java.io.File
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

    private fun checkMemoryMaps(): Boolean = try {
        File("/proc/self/maps").readText().let {
            it.contains("frida",     ignoreCase = true) ||
            it.contains("gadget",    ignoreCase = true) ||
            it.contains("substrate", ignoreCase = true) ||
            it.contains("xposed",    ignoreCase = true)
        }
    } catch (e: Exception) { false }

    private fun checkXposedStackTrace(): Boolean = try {
        Throwable().stackTrace.any {
            it.className.contains("xposed",          ignoreCase = true) ||
            it.className.contains("XposedBridge",    ignoreCase = true) ||
            it.className.contains("de.robv.android", ignoreCase = true)
        }
    } catch (e: Exception) { false }

    private fun checkSuExecution(): Boolean = try {
        val process  = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
        val finished = process.waitFor(300, TimeUnit.MILLISECONDS)
        if (finished) process.exitValue() == 0 else { process.destroy(); false }
    } catch (e: Exception) { false }

    fun scan(props: String): DetectorResult {
        // Compute all checks once — results reused in both signals and rawData
        val suFound      = suPaths.any { File(it).exists() }
        val bbFound      = bbPaths.any { File(it).exists() }
        val debuggable   = props.contains("ro.debuggable]: [1]")
        val secureOff    = props.contains("ro.secure]: [0]")
        val superuser    = File("/system/app/Superuser.apk").exists()
        val testKeys     = Build.TAGS.contains("test-keys", true)
        val devBuildType = Build.TYPE == "userdebug" || Build.TYPE == "eng"
        val xposed       = xposedPaths.any { File(it).exists() }
        val magisk       = magiskPaths.any { File(it).exists() }
        val apatch       = apatchPaths.any { File(it).exists() }
        val substrate    = substratePaths.any { File(it).exists() }
        val zygisk       = checkZygiskModules()
        val memMaps      = checkMemoryMaps()
        val xposedStack  = checkXposedStackTrace()
        val suExec       = checkSuExecution()

        val signals = listOf(
            Signal(SignalCategory.ROOT, "su binary found",                        "su binary not found",                 3, suFound),
            Signal(SignalCategory.ROOT, "busybox found",                          "busybox not found",                   2, bbFound),
            Signal(SignalCategory.ROOT, "ro.debuggable = 1 (rooted)",            "ro.debuggable = 0 (normal)",          3, debuggable),
            Signal(SignalCategory.ROOT, "ro.secure = 0 (rooted)",                "ro.secure = 1 (normal)",              3, secureOff),
            Signal(SignalCategory.ROOT, "Superuser.apk found",                    "Superuser.apk not found",             3, superuser),
            Signal(SignalCategory.ROOT, "Build TAGS: test-keys",                  "Build TAGS: release-keys",            2, testKeys),
            Signal(SignalCategory.ROOT, "Build.TYPE is userdebug / eng",          "Build.TYPE is user",                  2, devBuildType),
            Signal(SignalCategory.ROOT, "Xposed / LSPosed framework found",       "Xposed not detected",                 4, xposed),
            Signal(SignalCategory.ROOT, "Magisk files found",                     "Magisk not detected",                 4, magisk),
            Signal(SignalCategory.ROOT, "APatch files found",                     "APatch not detected",                 4, apatch),
            Signal(SignalCategory.ROOT, "Cydia Substrate SO found",              "Substrate not found",                 3, substrate),
            Signal(SignalCategory.ROOT, "Zygisk modules directory exists",       "No Zygisk modules",                   3, zygisk),
            Signal(SignalCategory.ROOT, "Frida / Substrate in /proc/self/maps",  "No hook library in memory maps",      4, memMaps),
            Signal(SignalCategory.ROOT, "Xposed hook in call stack",             "No Xposed in call stack",             4, xposedStack),
            Signal(SignalCategory.ROOT, "su command executes successfully",       "su command blocked",                  4, suExec),
        )

        val allPaths         = suPaths + listOf("/system/app/Superuser.apk") + bbPaths
        val fileResults      = allPaths.joinToString("\n") { "$it : ${if (File(it).exists()) "EXISTS" else "not found"}" }
        val debuggableLine   = props.lines().firstOrNull { it.contains("[ro.debuggable]") }?.trim() ?: "[ro.debuggable]: (not found)"
        val secureLine       = props.lines().firstOrNull { it.contains("[ro.secure]") }?.trim()     ?: "[ro.secure]: (not found)"
        val xposedResults    = xposedPaths.joinToString("\n")   { "$it : ${if (File(it).exists()) "EXISTS" else "not found"}" }
        val magiskResults    = magiskPaths.joinToString("\n")    { "$it : ${if (File(it).exists()) "EXISTS" else "not found"}" }
        val apatchResults    = apatchPaths.joinToString("\n")    { "$it : ${if (File(it).exists()) "EXISTS" else "not found"}" }
        val substrateResults = substratePaths.joinToString("\n") { "$it : ${if (File(it).exists()) "EXISTS" else "not found"}" }
        val zygiskLine       = "/data/adb/modules : ${if (zygisk) "EXISTS (has modules)" else "not found / empty"}"
        val mapsHits = try {
            File("/proc/self/maps").readLines()
                .filter { line -> listOf("frida", "gadget", "substrate", "xposed").any { line.contains(it, true) } }
                .joinToString("\n").ifEmpty { "(nothing suspicious)" }
        } catch (e: Exception) { "unavailable: ${e.message}" }

        val rawData = "=== Root / SU Files ===\n$fileResults\n\n" +
               "=== Xposed Files ===\n$xposedResults\n\n" +
               "=== Magisk Files ===\n$magiskResults\n\n" +
               "=== APatch Files ===\n$apatchResults\n\n" +
               "=== Substrate Files ===\n$substrateResults\n\n" +
               "=== Zygisk Modules ===\n$zygiskLine\n\n" +
               "=== System Props ===\n$debuggableLine\n$secureLine\n" +
               "TAGS: ${Build.TAGS}  TYPE: ${Build.TYPE}\n\n" +
               "=== /proc/self/maps (hook-related lines) ===\n$mapsHits"

        return DetectorResult(signals, rawData)
    }
}
