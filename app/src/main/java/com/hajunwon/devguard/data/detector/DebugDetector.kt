package com.hajunwon.devguard.data.detector

import android.content.Context
import android.os.Debug
import android.provider.Settings
import com.hajunwon.devguard.data.model.DetectorResult
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.io.File

object DebugDetector {

    private fun readTracerPid(): Int = try {
        File("/proc/self/status").readLines()
            .firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(":")
            ?.trim()
            ?.toIntOrNull() ?: 0
    } catch (e: Exception) { 0 }

    private fun checkFridaPort(port: Int): Boolean = try {
        java.net.Socket().use { it.connect(java.net.InetSocketAddress("127.0.0.1", port), 50); true }
    } catch (e: Exception) {
        // If Xposed hook threw this to block port scan, its frames appear in the stack
        e.stackTrace.any {
            it.className.contains("xposed", ignoreCase = true) ||
            it.className.contains("LSPHooker", ignoreCase = true)
        }
    }

    private fun checkFridaProcess(): Boolean = try {
        File("/proc").listFiles()
            ?.filter { it.name.matches(Regex("\\d+")) }
            ?.any { pid ->
                runCatching {
                    File("${pid.absolutePath}/cmdline").readText().lowercase().contains("frida")
                }.getOrDefault(false)
            } ?: false
    } catch (e: Exception) { false }

    suspend fun scan(context: Context): DetectorResult = coroutineScope {
        // Launch slow I/O operations in parallel
        val frida42Deferred   = async { checkFridaPort(27042) }
        val frida43Deferred   = async { checkFridaPort(27043) }
        val fridaProcDeferred = async { checkFridaProcess() }

        // Non-blocking checks run while ports are being probed
        val debuggerAttached = Debug.isDebuggerConnected()
        val tracerPid  = readTracerPid()
        val usbDebug   = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        val devOpts    = Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        @Suppress("DEPRECATION")
        val mockLoc    = Settings.Secure.getInt(context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION, 0) == 1
        val proxyHost  = System.getProperty("http.proxyHost") ?: ""
        val proxyPort  = System.getProperty("http.proxyPort") ?: ""
        val proxy      = proxyHost.isNotEmpty() && proxyPort.isNotEmpty()
        val a11y       = Settings.Secure.getString(
            context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        )?.isNotEmpty() == true

        // Await parallel results
        val frida42   = frida42Deferred.await()
        val frida43   = frida43Deferred.await()
        val fridaProc = fridaProcDeferred.await()

        val signals = listOf(
            Signal(SignalCategory.DEBUG, "Debugger attached (isDebuggerConnected)",  "No debugger attached",       4, debuggerAttached),
            Signal(SignalCategory.DEBUG, "TracerPid \u2260 0 (process being traced)", "TracerPid = 0 (not traced)", 4, tracerPid != 0),
            Signal(SignalCategory.DEBUG, "USB debugging enabled",                     "USB debugging disabled",     1, usbDebug),
            Signal(SignalCategory.DEBUG, "Developer options enabled",                "Developer options disabled", 1, devOpts),
            Signal(SignalCategory.DEBUG, "Mock location enabled",                    "Mock location disabled",     2, mockLoc),
            Signal(SignalCategory.DEBUG, "Frida server detected (port 27042)",       "No Frida on port 27042",     4, frida42),
            Signal(SignalCategory.DEBUG, "Frida server detected (port 27043)",       "No Frida on port 27043",     4, frida43),
            Signal(SignalCategory.DEBUG, "Frida process found in /proc",             "No Frida process in /proc",  4, fridaProc),
            Signal(SignalCategory.DEBUG, "HTTP proxy configured",                    "No HTTP proxy configured",   3, proxy),
            Signal(SignalCategory.DEBUG, "Accessibility services active",            "No accessibility services",  1, a11y),
        )

        val tracerLine = try {
            File("/proc/self/status").readLines()
                .firstOrNull { it.startsWith("TracerPid:") } ?: "TracerPid: (not found)"
        } catch (e: Exception) { "unavailable" }

        val rawData = listOf(
            "Debug.isDebuggerConnected()"                  to debuggerAttached.toString(),
            "Settings.Global.ADB_ENABLED"                  to usbDebug.toString(),
            "Settings.Global.DEVELOPMENT_SETTINGS_ENABLED" to devOpts.toString(),
            "Settings.Secure.ALLOW_MOCK_LOCATION"          to mockLoc.toString(),
            "TCP port 27042 (Frida)"                       to frida42.toString(),
            "TCP port 27043 (Frida alt)"                   to frida43.toString(),
            "Frida in /proc"                               to fridaProc.toString(),
            "HTTP Proxy Host"                              to proxyHost.ifEmpty { "(none)" },
            "HTTP Proxy Port"                              to proxyPort.ifEmpty { "(none)" },
        ).joinToString("\n") { "${it.first}: ${it.second}" } +
            "\n\n=== /proc/self/status (TracerPid) ===\n$tracerLine"

        DetectorResult(signals, rawData)
    }
}
