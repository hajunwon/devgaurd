package com.hajunwon.devguard.data.detector

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
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import android.telephony.TelephonyManager
import android.view.WindowManager
import java.io.File

object SystemInfoCollector {

    fun systemProperties(): String = try {
        Runtime.getRuntime().exec("getprop").inputStream.bufferedReader().readText()
    } catch (e: Exception) { "getprop failed: ${e.message}" }

    fun buildInfo(): String = listOf(
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

    fun displayInfo(context: Context): String {
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

    fun hardwareInfo(context: Context): String {
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

    fun sensorDetails(context: Context): String {
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

    fun networkInfo(context: Context): String {
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

    fun identifiers(context: Context): String {
        val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        return listOf(
            "Android ID" to (androidId ?: "null"),
            "Board"      to Build.BOARD,
            "Bootloader" to Build.BOOTLOADER,
            "Host"       to Build.HOST,
            "User"       to Build.USER
        ).joinToString("\n") { "${it.first}: ${it.second}" }
    }

    fun procInfo(): String {
        fun read(path: String) = try { File(path).readText() } catch (e: Exception) { "Failed: ${e.message}" }
        return "=== /proc/cpuinfo ===\n${read("/proc/cpuinfo")}\n\n" +
               "=== /proc/meminfo ===\n${read("/proc/meminfo")}\n\n" +
               "=== /proc/version ===\n${read("/proc/version")}"
    }

    fun batteryRaw(context: Context): String {
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

    fun batteryPercent(context: Context): Int {
        val i     = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = i?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = i?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        return if (scale > 0) level * 100 / scale else -1
    }
}
