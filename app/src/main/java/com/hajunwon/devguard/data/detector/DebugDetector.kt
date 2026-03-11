package com.hajunwon.devguard.data.detector

import android.content.Context
import android.os.Debug
import android.provider.Settings
import com.hajunwon.devguard.data.model.DetectorResult
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import com.hajunwon.devguard.data.model.SignalLayer
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

    /**
     * Parses /proc/net/tcp directly to find Frida listening ports (27042–27044).
     * Unlike Socket.connect(), this bypasses any Xposed hook on the socket API.
     * Format: "sl local_address(hex) rem_address st ..." — state 0A = LISTEN.
     */
    private fun checkFridaViaTcp(): Boolean = try {
        val fridaPorts = setOf(27042, 27043, 27044)
        listOf("/proc/net/tcp", "/proc/net/tcp6").any { tcpFile ->
            try {
                File(tcpFile).readLines().drop(1).any { line ->
                    val parts   = line.trim().split(Regex("\\s+"))
                    val portHex = parts.getOrNull(1)?.substringAfter(":") ?: return@any false
                    val port    = portHex.toIntOrNull(16) ?: return@any false
                    val state   = parts.getOrNull(3) ?: return@any false
                    state == "0A" && port in fridaPorts  // 0A = LISTEN
                }
            } catch (_: Exception) { false }
        }
    } catch (e: Exception) { false }

    /**
     * Scans /proc/net/unix for Frida IPC sockets.
     * Frida Gadget/server creates Unix domain sockets with "frida" in the path
     * even when renamed or running on a non-standard port.
     */
    private fun checkFridaUnixSocket(): Boolean = try {
        File("/proc/net/unix").readLines()
            .any { line -> line.contains("frida", ignoreCase = true) }
    } catch (e: Exception) { false }

    private fun checkFridaProcess(): Boolean = try {
        File("/proc").listFiles()
            ?.filter { it.name.matches(Regex("\\d+")) }
            ?.any { pid ->
                runCatching {
                    File("${pid.absolutePath}/cmdline").readText().lowercase().contains("frida")
                }.getOrDefault(false)
            } ?: false
    } catch (e: Exception) { false }

    private fun checkGdbserverProcess(): Boolean = try {
        File("/proc").listFiles()
            ?.filter { it.name.matches(Regex("\\d+")) }
            ?.any { pid ->
                runCatching {
                    val cmd = File("${pid.absolutePath}/cmdline").readText().lowercase()
                    cmd.contains("gdbserver") || cmd.contains("gdb.server")
                }.getOrDefault(false)
            } ?: false
    } catch (e: Exception) { false }

    /**
     * Scans /proc/net/tcp and /proc/net/tcp6 for JDWP debugger ports (8600, 8700).
     * State 0A = LISTEN. Uses raw proc files to bypass any socket API hook.
     */
    private fun checkJdwpPort(): Boolean = try {
        val jdwpPorts = setOf(8600, 8700)
        listOf("/proc/net/tcp", "/proc/net/tcp6").any { tcpFile ->
            try {
                File(tcpFile).readLines().drop(1).any { line ->
                    val parts   = line.trim().split(Regex("\\s+"))
                    val portHex = parts.getOrNull(1)?.substringAfter(":") ?: return@any false
                    val port    = portHex.toIntOrNull(16) ?: return@any false
                    val state   = parts.getOrNull(3) ?: return@any false
                    state == "0A" && port in jdwpPorts
                }
            } catch (_: Exception) { false }
        }
    } catch (e: Exception) { false }

    /** /data/local/tmp world-writable = rooted device (world-write permission set) */
    private fun checkLocalTmpWritable(): Boolean = try {
        File("/data/local/tmp").let { f -> f.exists() && f.canWrite() }
    } catch (e: Exception) { false }

    /** Frida server binary staged in /data/local/tmp */
    private fun checkFridaStagingFiles(): Boolean =
        File("/data/local/tmp/frida-server").exists() ||
        File("/data/local/tmp/re.frida.server").exists() ||
        File("/data/local/tmp/frida").exists()

    suspend fun scan(context: Context): DetectorResult = coroutineScope {
        // Launch slow I/O operations in parallel
        val frida42Deferred    = async { checkFridaPort(27042) }
        val frida43Deferred    = async { checkFridaPort(27043) }
        val fridaProcDeferred  = async { checkFridaProcess() }
        val fridaUnixDeferred  = async { checkFridaUnixSocket() }
        val fridaTcpDeferred   = async { checkFridaViaTcp() }
        val gdbSrvDeferred     = async { checkGdbserverProcess() }
        val jdwpDeferred       = async { checkJdwpPort() }

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
        val localTmpWritable = checkLocalTmpWritable()
        val fridaStaging     = checkFridaStagingFiles()

        // Await parallel results
        val frida42    = frida42Deferred.await()
        val frida43    = frida43Deferred.await()
        val fridaProc  = fridaProcDeferred.await()
        val fridaUnix  = fridaUnixDeferred.await()
        val fridaTcp   = fridaTcpDeferred.await()
        val gdbSrv     = gdbSrvDeferred.await()
        val jdwpOpen   = jdwpDeferred.await()

        val jvmSignals = listOf(
            Signal(SignalCategory.DEBUG, "Debugger attached (isDebuggerConnected)",  "No debugger attached",           4, debuggerAttached),
            Signal(SignalCategory.DEBUG, "TracerPid \u2260 0 (process being traced)", "TracerPid = 0 (not traced)",   4, tracerPid != 0,  group = "dbg_tracer"),
            Signal(SignalCategory.DEBUG, "USB debugging enabled",                     "USB debugging disabled",         1, usbDebug),
            Signal(SignalCategory.DEBUG, "Developer options enabled",                "Developer options disabled",     1, devOpts),
            Signal(SignalCategory.DEBUG, "Mock location enabled",                    "Mock location disabled",         2, mockLoc),
            Signal(SignalCategory.DEBUG, "Frida server detected (port 27042)",       "No Frida on port 27042",         4, frida42,         group = "dbg_frida_27042"),
            Signal(SignalCategory.DEBUG, "Frida server detected (port 27043)",       "No Frida on port 27043",         4, frida43,         group = "dbg_frida_27043"),
            Signal(SignalCategory.DEBUG, "Frida process found in /proc",             "No Frida process in /proc",      4, fridaProc,       group = "dbg_frida_proc"),
            Signal(SignalCategory.DEBUG, "Frida Unix socket in /proc/net/unix",     "No Frida Unix socket",           4, fridaUnix),
            Signal(SignalCategory.DEBUG, "Frida port in /proc/net/tcp (hook-safe)", "No Frida port in /proc/net/tcp", 4, fridaTcp),
            Signal(SignalCategory.DEBUG, "HTTP proxy configured",                    "No HTTP proxy configured",       3, proxy),
            Signal(SignalCategory.DEBUG, "Accessibility services active",            "No accessibility services",      1, a11y),
            Signal(SignalCategory.DEBUG, "gdbserver process detected in /proc",     "No gdbserver process",           4, gdbSrv),
            Signal(SignalCategory.DEBUG, "JDWP debugger port open (8600/8700)",     "No JDWP port detected",          4, jdwpOpen),
            Signal(SignalCategory.DEBUG, "/data/local/tmp is writable (staging)",   "/data/local/tmp restricted",     3, localTmpWritable),
            Signal(SignalCategory.DEBUG, "Frida server file in /data/local/tmp",    "No Frida staging files",         4, fridaStaging),
        )

        val jniSignals: List<Signal> = if (NativeDetector.isAvailable) listOf(
            Signal(SignalCategory.DEBUG, "ptrace self-check (PTRACE_TRACEME)", "ptrace OK (not traced)",      4, NativeDetector.nativeCheckPtrace(),             SignalLayer.JNI),
            Signal(SignalCategory.DEBUG, "TracerPid \u2260 0 (libc read)",     "TracerPid = 0 (libc)",        4, NativeDetector.nativeReadTracerPid() != 0,      SignalLayer.JNI, "dbg_tracer"),
            Signal(SignalCategory.DEBUG, "Frida port 27042 (socket)",          "No Frida on 27042",           4, NativeDetector.nativeCheckFridaPort(27042),     SignalLayer.JNI, "dbg_frida_27042"),
            Signal(SignalCategory.DEBUG, "Frida port 27043 (socket)",          "No Frida on 27043",           4, NativeDetector.nativeCheckFridaPort(27043),     SignalLayer.JNI, "dbg_frida_27043"),
            Signal(SignalCategory.DEBUG, "Frida process in /proc (libc)",      "No Frida process",            4, NativeDetector.nativeCheckFridaProcess(),       SignalLayer.JNI, "dbg_frida_proc"),
        ) else emptyList()

        val syscallTracerPid = NativeDetector.isAvailable && NativeDetector.syscallReadTracerPid() != 0
        val syscallFridaProc = NativeDetector.isAvailable && NativeDetector.syscallCheckFridaProcess()

        val syscallSignals: List<Signal> = if (NativeDetector.isAvailable) listOf(
            Signal(SignalCategory.DEBUG, "TracerPid \u2260 0 (syscall read)", "TracerPid = 0 (syscall)",   4, syscallTracerPid, SignalLayer.SYSCALL, "dbg_tracer"),
            Signal(SignalCategory.DEBUG, "Frida process in /proc (syscall)",  "No Frida process",          4, syscallFridaProc, SignalLayer.SYSCALL, "dbg_frida_proc"),
        ) else emptyList()

        val signals = jvmSignals + jniSignals + syscallSignals

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
            "Frida Unix socket (/proc/net/unix)"           to fridaUnix.toString(),
            "Frida port via /proc/net/tcp[6]"              to fridaTcp.toString(),
            "gdbserver in /proc"                           to gdbSrv.toString(),
            "JDWP port 8600/8700"                          to jdwpOpen.toString(),
            "/data/local/tmp writable"                     to localTmpWritable.toString(),
            "Frida staging files"                          to fridaStaging.toString(),
            "HTTP Proxy Host"                              to proxyHost.ifEmpty { "(none)" },
            "HTTP Proxy Port"                              to proxyPort.ifEmpty { "(none)" },
        ).joinToString("\n") { "${it.first}: ${it.second}" } +
            "\n\n=== /proc/self/status (TracerPid) ===\n$tracerLine"

        DetectorResult(signals, rawData)
    }
}
