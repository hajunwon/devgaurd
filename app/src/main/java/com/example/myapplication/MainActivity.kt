package com.example.myapplication

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.Sensor
import android.hardware.SensorManager
import android.hardware.camera2.CameraManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import android.telephony.TelephonyManager
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.myapplication.ui.theme.MyApplicationTheme
import java.io.File

// ── Data ─────────────────────────────────────────────────────────────────────

enum class SignalCategory { EMULATOR, ROOT, DEBUG }

data class Signal(
    val category: SignalCategory,
    val detectedText: String,   // triggered = true 일 때 표시
    val passText: String,        // triggered = false 일 때 표시
    val weight: Int,
    val triggered: Boolean
)

data class RiskLevel(val label: String, val subtitle: String, val color: Color)

// ── Detection ─────────────────────────────────────────────────────────────────

fun collectEmulatorSignals(props: String): List<Signal> {
    val hw    = Build.HARDWARE.lowercase()
    val model = Build.MODEL.lowercase()
    val radio = Build.getRadioVersion()
    val ttyDrivers = try { File("/proc/tty/drivers").readText() } catch (e: Exception) { "" }
    return listOf(
        Signal(SignalCategory.EMULATOR, "ro.kernel.qemu = 1 (QEMU detected)",     "ro.kernel.qemu not set",               4, props.contains("ro.kernel.qemu]: [1]")),
        Signal(SignalCategory.EMULATOR, "ABI is x86 (emulator pattern)",          "ABI is ARM (real device)",             2, Build.SUPPORTED_ABIS.any { it.contains("x86") }),
        Signal(SignalCategory.EMULATOR, "FINGERPRINT contains 'generic'",         "FINGERPRINT looks like real device",   2, Build.FINGERPRINT.contains("generic", true)),
        Signal(SignalCategory.EMULATOR, "Hardware: goldfish / ranchu",            "Hardware is not emulator chipset",     4, hw.contains("goldfish") || hw.contains("ranchu")),
        Signal(SignalCategory.EMULATOR, "Model matches sdk / gphone / emulator", "Model looks like real device",         3, model.contains("sdk") || model.contains("gphone") || model.contains("emulator")),
        Signal(SignalCategory.EMULATOR, "Build TAGS: test-keys",                  "Build TAGS: release-keys",             1, Build.TAGS.contains("test-keys", true)),
        Signal(SignalCategory.EMULATOR, "QEMU device files found (/dev/qemu_pipe)","QEMU device files not found",         3, File("/dev/qemu_pipe").exists() || File("/dev/socket/qemud").exists()),
        Signal(SignalCategory.EMULATOR, "Build.RADIO is unknown / empty",         "Build.RADIO has real value",           2, radio.isNullOrEmpty() || radio == Build.UNKNOWN),
        Signal(SignalCategory.EMULATOR, "/proc/tty/drivers contains 'goldfish'",  "/proc/tty/drivers looks normal",       2, ttyDrivers.contains("goldfish", true)),
    )
}

private fun checkXposed(): Boolean = listOf(
    "/system/framework/XposedBridge.jar",
    "/system/lib/libxposed_art.so",
    "/system/lib64/libxposed_art.so",
    "/data/adb/lspatch"
).any { File(it).exists() }

private fun checkMemoryMaps(): Boolean = try {
    File("/proc/self/maps").readText().let {
        it.contains("frida",     ignoreCase = true) ||
        it.contains("gadget",    ignoreCase = true) ||
        it.contains("substrate", ignoreCase = true)
    }
} catch (e: Exception) { false }

fun collectRootSignals(props: String): List<Signal> {
    val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/adb/magisk", "/data/adb/ksu")
    val bbPaths = listOf("/system/bin/busybox", "/system/xbin/busybox", "/sbin/busybox")
    return listOf(
        Signal(SignalCategory.ROOT, "su binary found",                      "su binary not found",                  3, suPaths.any { File(it).exists() }),
        Signal(SignalCategory.ROOT, "busybox found",                        "busybox not found",                    2, bbPaths.any { File(it).exists() }),
        Signal(SignalCategory.ROOT, "ro.debuggable = 1 (rooted)",          "ro.debuggable = 0 (normal)",           3, props.contains("ro.debuggable]: [1]")),
        Signal(SignalCategory.ROOT, "ro.secure = 0 (rooted)",              "ro.secure = 1 (normal)",               3, props.contains("ro.secure]: [0]")),
        Signal(SignalCategory.ROOT, "Superuser.apk found",                  "Superuser.apk not found",              3, File("/system/app/Superuser.apk").exists()),
        Signal(SignalCategory.ROOT, "Xposed / LSPosed framework found",     "Xposed not detected",                  4, checkXposed()),
        Signal(SignalCategory.ROOT, "Frida / Substrate in /proc/self/maps","No hook library in memory maps",        4, checkMemoryMaps()),
    )
}

fun collectDebugSignals(context: Context): List<Signal> {
    val usbDebug = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    val devOpts  = Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
    @Suppress("DEPRECATION")
    val mockLoc  = Settings.Secure.getInt(context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION, 0) == 1
    val frida    = try {
        java.net.Socket().use { it.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 50); true }
    } catch (e: Exception) { false }
    return listOf(
        Signal(SignalCategory.DEBUG, "Debugger attached",             "No debugger attached",         4, Debug.isDebuggerConnected()),
        Signal(SignalCategory.DEBUG, "USB debugging enabled",        "USB debugging disabled",       1, usbDebug),
        Signal(SignalCategory.DEBUG, "Developer options enabled",    "Developer options disabled",   1, devOpts),
        Signal(SignalCategory.DEBUG, "Mock location enabled",        "Mock location disabled",       2, mockLoc),
        Signal(SignalCategory.DEBUG, "Frida server detected (27042)", "Frida server not detected",   4, frida),
        Signal(SignalCategory.DEBUG, "Accessibility services active",  "No accessibility services",  1,
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)?.isNotEmpty() == true),
    )
}

fun collectAllSignals(context: Context, props: String): List<Signal> =
    collectEmulatorSignals(props) + collectRootSignals(props) + collectDebugSignals(context)

fun calculateScore(signals: List<Signal>): Int =
    signals.filter { it.triggered }.sumOf { it.weight }

fun getRiskLevel(score: Int): RiskLevel = when {
    score >= 10 -> RiskLevel("COMPROMISED", "Emulator or heavily modified", Color(0xFFB71C1C))
    score >= 7  -> RiskLevel("EMULATOR",    "Likely an emulator",           Color(0xFFEF5350))
    score >= 5  -> RiskLevel("HIGH RISK",   "Rooted or dev environment",    Color(0xFFFF5722))
    score >= 3  -> RiskLevel("SUSPICIOUS",  "Some risk signals detected",   Color(0xFFFF9800))
    score >= 1  -> RiskLevel("LOW RISK",    "Minor signals detected",       Color(0xFFFFC107))
    else        -> RiskLevel("CLEAN",       "No suspicious signals",        Color(0xFF4CAF50))
}

// ── Data Collection ───────────────────────────────────────────────────────────

fun collectSystemProperties(): String = try {
    Runtime.getRuntime().exec("getprop").inputStream.bufferedReader().readText()
} catch (e: Exception) { "getprop failed: ${e.message}" }

fun collectBuildInfo(): String = listOf(
    "MODEL"          to Build.MODEL,
    "BRAND"          to Build.BRAND,
    "MANUFACTURER"   to Build.MANUFACTURER,
    "DEVICE"         to Build.DEVICE,
    "HARDWARE"       to Build.HARDWARE,
    "FINGERPRINT"    to Build.FINGERPRINT,
    "TAGS"           to Build.TAGS,
    "TYPE"           to Build.TYPE,
    "SDK_INT"        to Build.VERSION.SDK_INT.toString(),
    "RELEASE"        to Build.VERSION.RELEASE,
    "SUPPORTED_ABIS" to Build.SUPPORTED_ABIS.joinToString()
).joinToString("\n") { "${it.first}: ${it.second}" }

fun collectDisplayInfo(context: Context): String {
    val dm = context.resources.displayMetrics
    val bucket = when {
        dm.densityDpi <= 120 -> "ldpi"
        dm.densityDpi <= 160 -> "mdpi"
        dm.densityDpi <= 240 -> "hdpi"
        dm.densityDpi <= 320 -> "xhdpi"
        dm.densityDpi <= 480 -> "xxhdpi"
        else                 -> "xxxhdpi"
    }
    val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    @Suppress("DEPRECATION")
    val refreshRate = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        context.display?.refreshRate ?: -1f
    else
        wm.defaultDisplay.refreshRate
    val brightness = try {
        Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_BRIGHTNESS)
    } catch (e: Exception) { -1 }
    return listOf(
        "Resolution"   to "${dm.widthPixels} x ${dm.heightPixels} px",
        "DPI"          to "${dm.densityDpi} ($bucket)",
        "Refresh rate" to "${refreshRate.toInt()} Hz",
        "Font scale"   to context.resources.configuration.fontScale.toString(),
        "Brightness"   to "$brightness / 255"
    ).joinToString("\n") { "${it.first}: ${it.second}" }
}

fun collectHardwareInfo(context: Context): String {
    val am      = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    val memInfo = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
    fun Long.toMB() = this / (1024 * 1024)
    val maxFreqMhz = try {
        File("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq").readText().trim().toLong() / 1000
    } catch (e: Exception) { -1L }
    val cameraCount = try {
        (context.getSystemService(Context.CAMERA_SERVICE) as CameraManager).cameraIdList.size
    } catch (e: Exception) { -1 }
    val stat = StatFs(Environment.getDataDirectory().path)
    return listOf(
        "CPU cores"     to Runtime.getRuntime().availableProcessors().toString(),
        "CPU max freq"  to if (maxFreqMhz > 0) "${maxFreqMhz} MHz" else "unknown",
        "ABI"           to Build.SUPPORTED_ABIS.joinToString(),
        "Total RAM"     to "${memInfo.totalMem.toMB()} MB",
        "Available RAM" to "${memInfo.availMem.toMB()} MB",
        "Total Storage" to "${stat.totalBytes / (1024 * 1024 * 1024)} GB",
        "Free Storage"  to "${stat.availableBytes / (1024 * 1024)} MB",
        "Camera count"  to cameraCount.toString()
    ).joinToString("\n") { "${it.first}: ${it.second}" }
}

fun collectSensorDetails(context: Context): String {
    val sm    = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    val total = sm.getSensorList(Sensor.TYPE_ALL).size
    val checks = listOf(
        Sensor.TYPE_ACCELEROMETER  to "Accelerometer",
        Sensor.TYPE_GYROSCOPE      to "Gyroscope",
        Sensor.TYPE_MAGNETIC_FIELD to "Magnetometer",
        Sensor.TYPE_PROXIMITY      to "Proximity",
        Sensor.TYPE_LIGHT          to "Light",
        Sensor.TYPE_PRESSURE       to "Barometer",
        Sensor.TYPE_STEP_COUNTER   to "Step Counter",
        Sensor.TYPE_HEART_RATE     to "Heart Rate",
    )
    val detail = checks.joinToString("\n") { (type, name) ->
        val s = sm.getDefaultSensor(type)
        "$name: ${if (s != null) "YES  (${s.name})" else "NO"}"
    }
    return "Total sensors: $total\n\n$detail"
}

fun collectNetworkInfo(context: Context): String {
    val cm   = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val caps = cm.getNetworkCapabilities(cm.activeNetwork)
    val tm   = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
    val op   = tm.networkOperator
    val mccMnc = if (!op.isNullOrEmpty() && op.length >= 5)
        "MCC: ${op.substring(0, 3)}, MNC: ${op.substring(3)}"
    else "N/A"
    return listOf(
        "WiFi"          to (caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)?.toString() ?: "false"),
        "Cellular"      to (caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)?.toString() ?: "false"),
        "VPN"           to (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)?.toString() ?: "false"),
        "MCC / MNC"     to mccMnc,
        "SIM state"     to tm.simState.toString(),
        "Operator name" to tm.simOperatorName.ifEmpty { "N/A" }
    ).joinToString("\n") { "${it.first}: ${it.second}" }
}

fun collectIdentifiers(context: Context): String {
    val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
    return listOf(
        "Android ID" to (androidId ?: "null"),
        "Board"      to Build.BOARD,
        "Bootloader" to Build.BOOTLOADER,
        "Host"       to Build.HOST,
        "User"       to Build.USER
    ).joinToString("\n") { "${it.first}: ${it.second}" }
}

fun collectProcInfo(): String {
    fun read(path: String) = try { File(path).readText() } catch (e: Exception) { "Failed: ${e.message}" }
    return "=== /proc/cpuinfo ===\n${read("/proc/cpuinfo")}\n\n" +
           "=== /proc/meminfo ===\n${read("/proc/meminfo")}\n\n" +
           "=== /proc/version ===\n${read("/proc/version")}"
}

// ── Raw Sources (for Raw tab) ─────────────────────────────────────────────────

fun collectEmulatorRaw(props: String): String {
    val qemuLine   = props.lines().firstOrNull { it.contains("ro.kernel.qemu") }?.trim() ?: "[ro.kernel.qemu]: (not found)"
    val ttyDrivers = try { File("/proc/tty/drivers").readText() } catch (e: Exception) { "unavailable" }
    return listOf(
        "HARDWARE"          to Build.HARDWARE,
        "FINGERPRINT"       to Build.FINGERPRINT,
        "SUPPORTED_ABIS"    to Build.SUPPORTED_ABIS.joinToString(),
        "MODEL"             to Build.MODEL,
        "TAGS"              to Build.TAGS,
        "RADIO"             to (Build.getRadioVersion() ?: "null"),
        "/dev/qemu_pipe"    to File("/dev/qemu_pipe").exists().toString(),
        "/dev/socket/qemud" to File("/dev/socket/qemud").exists().toString(),
    ).joinToString("\n") { "${it.first}: ${it.second}" } +
        "\n\n$qemuLine" +
        "\n\n=== /proc/tty/drivers ===\n$ttyDrivers"
}

fun collectRootRaw(props: String): String {
    val paths = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/data/adb/magisk", "/data/adb/ksu",
        "/system/app/Superuser.apk",
        "/system/bin/busybox", "/system/xbin/busybox"
    )
    val fileResults = paths.joinToString("\n") { "$it : ${if (File(it).exists()) "EXISTS" else "not found"}" }
    val debuggable = props.lines().firstOrNull { it.contains("[ro.debuggable]") }?.trim() ?: "[ro.debuggable]: (not found)"
    val secure     = props.lines().firstOrNull { it.contains("[ro.secure]") }?.trim()     ?: "[ro.secure]: (not found)"
    val xposedPaths = listOf(
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/data/adb/lspatch"
    )
    val xposedResults = xposedPaths.joinToString("\n") { "$it : ${if (File(it).exists()) "EXISTS" else "not found"}" }
    val mapsHits = try {
        File("/proc/self/maps").readLines()
            .filter { line -> listOf("frida", "gadget", "substrate").any { line.contains(it, true) } }
            .joinToString("\n").ifEmpty { "(nothing suspicious)" }
    } catch (e: Exception) { "unavailable: ${e.message}" }
    return "=== Root / SU Files ===\n$fileResults\n\n" +
           "=== Xposed Files ===\n$xposedResults\n\n" +
           "=== System Props ===\n$debuggable\n$secure\n\n" +
           "=== /proc/self/maps (hook-related lines) ===\n$mapsHits"
}

fun collectDebugRaw(context: Context): String {
    val usbDebug = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0)
    val devOpts  = Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0)
    @Suppress("DEPRECATION")
    val mockLoc  = Settings.Secure.getInt(context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION, 0)
    return listOf(
        "Debug.isDebuggerConnected()"              to Debug.isDebuggerConnected().toString(),
        "Settings.Global.ADB_ENABLED"              to usbDebug.toString(),
        "Settings.Global.DEVELOPMENT_SETTINGS_ENABLED" to devOpts.toString(),
        "Settings.Secure.ALLOW_MOCK_LOCATION"      to mockLoc.toString(),
        "TCP port 27042 (Frida)"                   to "(evaluated at scan time)"
    ).joinToString("\n") { "${it.first}: ${it.second}" }
}

fun collectBatteryRaw(context: Context): String {
    val i      = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
    val level  = i?.getIntExtra(BatteryManager.EXTRA_LEVEL,       -1) ?: -1
    val scale  = i?.getIntExtra(BatteryManager.EXTRA_SCALE,       -1) ?: -1
    val status = i?.getIntExtra(BatteryManager.EXTRA_STATUS,      -1) ?: -1
    val health = i?.getIntExtra(BatteryManager.EXTRA_HEALTH,      -1) ?: -1
    val temp   = i?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1
    val volt   = i?.getIntExtra(BatteryManager.EXTRA_VOLTAGE,     -1) ?: -1
    val plugged= i?.getIntExtra(BatteryManager.EXTRA_PLUGGED,     -1) ?: -1
    val pct    = if (scale > 0) level * 100 / scale else -1
    return listOf(
        "EXTRA_LEVEL"       to "$level / $scale  ($pct%)",
        "EXTRA_STATUS"      to when (status) {
            BatteryManager.BATTERY_STATUS_CHARGING     -> "Charging ($status)"
            BatteryManager.BATTERY_STATUS_DISCHARGING  -> "Discharging ($status)"
            BatteryManager.BATTERY_STATUS_FULL         -> "Full ($status)"
            BatteryManager.BATTERY_STATUS_NOT_CHARGING -> "Not Charging ($status)"
            else -> "Unknown ($status)"
        },
        "EXTRA_HEALTH"      to when (health) {
            BatteryManager.BATTERY_HEALTH_GOOD          -> "Good ($health)"
            BatteryManager.BATTERY_HEALTH_OVERHEAT      -> "Overheat ($health)"
            BatteryManager.BATTERY_HEALTH_DEAD          -> "Dead ($health)"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE  -> "Over Voltage ($health)"
            else -> "Unknown ($health)"
        },
        "EXTRA_TEMPERATURE" to "${temp / 10.0} °C  (raw: $temp)",
        "EXTRA_VOLTAGE"     to "$volt mV",
        "EXTRA_PLUGGED"     to when (plugged) {
            BatteryManager.BATTERY_PLUGGED_AC       -> "AC ($plugged)"
            BatteryManager.BATTERY_PLUGGED_USB      -> "USB ($plugged)"
            BatteryManager.BATTERY_PLUGGED_WIRELESS -> "Wireless ($plugged)"
            0 -> "Not plugged (0)"
            else -> "Unknown ($plugged)"
        }
    ).joinToString("\n") { "${it.first}: ${it.second}" }
}

// ── UI Components ─────────────────────────────────────────────────────────────

@Composable
fun RiskBadge(label: String, subtitle: String, score: Int, color: Color) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(color.copy(alpha = 0.10f))
                .padding(28.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.displaySmall,
                fontWeight = FontWeight.Bold,
                color = color
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = color.copy(alpha = 0.8f)
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "Risk score: $score",
                style = MaterialTheme.typography.titleMedium,
                color = color.copy(alpha = 0.6f)
            )
        }
    }
}

@Composable
fun InfoCard(title: String, content: String, titleColor: Color = Color.Unspecified) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = if (titleColor != Color.Unspecified) titleColor
                        else MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = content,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun SignalGroupCard(category: SignalCategory, signals: List<Signal>) {
    val alertColor = when (category) {
        SignalCategory.EMULATOR -> Color(0xFFEF5350)
        SignalCategory.ROOT     -> Color(0xFFFF5722)
        SignalCategory.DEBUG    -> Color(0xFFFF9800)
    }
    val safeColor  = Color(0xFF4CAF50)
    val titleColor = if (signals.any { it.triggered }) alertColor else safeColor

    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = category.name,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = titleColor
            )
            Spacer(Modifier.height(10.dp))
            signals.forEach { signal ->
                val color = if (signal.triggered) alertColor else safeColor
                Row(
                    modifier = Modifier.padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = if (signal.triggered) "✗" else "✓",
                        color = color,
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = if (signal.triggered) "${signal.detectedText}  (+${signal.weight})" else signal.passText,
                        color = color,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}

@Composable
fun CollapsibleInfoCard(title: String, content: String) {
    var expanded by remember { mutableStateOf(false) }
    val arrowAngle by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        label = "arrow"
    )
    ElevatedCard(
        onClick = { expanded = !expanded },
        modifier = Modifier
            .fillMaxWidth()
            .animateContentSize(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
                Icon(
                    imageVector = Icons.Filled.KeyboardArrowDown,
                    contentDescription = null,
                    modifier = Modifier.rotate(arrowAngle),
                    tint = MaterialTheme.colorScheme.primary
                )
            }
            if (expanded) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Spacer(Modifier.height(8.dp))
                Text(
                    text = content,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ── Screens ───────────────────────────────────────────────────────────────────

@Composable
fun DashboardScreen() {
    val context = LocalContext.current
    var refreshKey by remember { mutableStateOf(0) }

    val props   = remember(refreshKey) { collectSystemProperties() }
    val signals = remember(refreshKey) { collectAllSignals(context, props) }
    val score   = calculateScore(signals)
    val risk    = getRiskLevel(score)

    val batteryPercent = remember(refreshKey) {
        val intent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level  = intent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale  = intent?.getIntExtra(BatteryManager.EXTRA_SCALE,  -1) ?: -1
        if (scale > 0) level * 100 / scale else -1
    }

    val dm = context.resources.displayMetrics

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        RiskBadge(label = risk.label, subtitle = risk.subtitle, score = score, color = risk.color)

        SignalCategory.values().forEach { cat ->
            SignalGroupCard(
                category = cat,
                signals  = signals.filter { it.category == cat }
            )
        }

        InfoCard("Device",  "${Build.MANUFACTURER} ${Build.MODEL}\nAndroid ${Build.VERSION.RELEASE}  ·  SDK ${Build.VERSION.SDK_INT}")
        InfoCard("Display", "${dm.widthPixels} × ${dm.heightPixels}  ·  ${dm.densityDpi} DPI")
        InfoCard("CPU",     "${Runtime.getRuntime().availableProcessors()} cores  ·  ${Build.HARDWARE}")
        InfoCard("Battery", "Level: $batteryPercent%")

        Button(
            onClick = { refreshKey++ },
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            shape = RoundedCornerShape(14.dp)
        ) {
            Text("Re-scan", style = MaterialTheme.typography.titleMedium)
        }

        Spacer(Modifier.height(8.dp))
    }
}

@Composable
fun RawScreen() {
    val context = LocalContext.current
    val props = remember { collectSystemProperties() }

    // Signal detection sources
    val emulatorRaw  = remember { collectEmulatorRaw(props) }
    val rootRaw      = remember { collectRootRaw(props) }
    val debugRaw     = remember { collectDebugRaw(context) }

    // Dashboard card sources
    val buildInfo    = remember { collectBuildInfo() }
    val displayInfo  = remember { collectDisplayInfo(context) }
    val hardwareInfo = remember { collectHardwareInfo(context) }
    val batteryRaw   = remember { collectBatteryRaw(context) }

    // Extra raw data
    val sensorInfo   = remember { collectSensorDetails(context) }
    val networkInfo  = remember { collectNetworkInfo(context) }
    val identifiers  = remember { collectIdentifiers(context) }
    val procInfo     = remember { collectProcInfo() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // ── Signal sources ────────────────────────────────────────────────────
        CollapsibleInfoCard("Emulator Signal Sources", emulatorRaw)
        CollapsibleInfoCard("Root Signal Sources",     rootRaw)
        CollapsibleInfoCard("Debug Signal Sources",    debugRaw)

        // ── Dashboard card sources ────────────────────────────────────────────
        CollapsibleInfoCard("Build Info",              buildInfo)
        CollapsibleInfoCard("Display Metrics",         displayInfo)
        CollapsibleInfoCard("Hardware & Memory",       hardwareInfo)
        CollapsibleInfoCard("Battery",                 batteryRaw)

        // ── Extra ─────────────────────────────────────────────────────────────
        CollapsibleInfoCard("Sensors",                 sensorInfo)
        CollapsibleInfoCard("Network",                 networkInfo)
        CollapsibleInfoCard("Identifiers",             identifiers)
        CollapsibleInfoCard("System Properties",       props)
        CollapsibleInfoCard("/proc Info",              procInfo)
    }
}

@Composable
fun DeviceInfoScreen() {
    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("Dashboard", "Raw")

    Column {
        TabRow(selectedTabIndex = selectedTab) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = selectedTab == index,
                    onClick  = { selectedTab = index },
                    text     = { Text(title) }
                )
            }
        }
        when (selectedTab) {
            0 -> DashboardScreen()
            1 -> RawScreen()
        }
    }
}

// ── Activity ──────────────────────────────────────────────────────────────────

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    DeviceInfoScreen()
                }
            }
        }
    }
}
