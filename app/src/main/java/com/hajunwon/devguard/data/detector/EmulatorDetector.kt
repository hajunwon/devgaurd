package com.hajunwon.devguard.data.detector

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.telephony.TelephonyManager
import com.hajunwon.devguard.data.model.DetectorResult
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import java.io.File

object EmulatorDetector {

    // Merged MODEL + PRODUCT check to avoid double-counting on AVD
    // (AVD sets MODEL == PRODUCT == "sdk_gphone_x86")
    private fun checkEmulatorModelOrProduct(): Boolean {
        val model   = Build.MODEL.lowercase()
        val product = Build.PRODUCT.lowercase()
        val patterns = listOf(
            "sdk_gphone", "vbox86p", "generic_x86", "generic_x86_64",
            "sdk_x86", "google_sdk", "emulator", "android sdk built for x86"
        )
        return patterns.any { model.contains(it) || product.contains(it) } ||
               product == "generic"
    }

    private fun checkBlueStacks(): Boolean =
        File("/data/bluestacks.prop").exists() ||
        File("/data/data/com.bluestacks.home").exists() ||
        Build.BRAND.lowercase().contains("bluestacks") ||
        Build.MANUFACTURER.lowercase().contains("bluestacks")

    private fun checkNox(): Boolean =
        File("/data/nox.prop").exists() ||
        Build.HARDWARE.lowercase().contains("nox") ||
        Build.MODEL.lowercase().contains("nox")

    private fun checkLDPlayer(): Boolean =
        Build.HARDWARE.lowercase().contains("ldmps") ||
        Build.MANUFACTURER.lowercase().contains("ldplayer") ||
        Build.MODEL.lowercase().contains("ldplayer")

    private fun checkSuspiciousHostUser(): Boolean {
        val host = Build.HOST.lowercase()
        val user = Build.USER.lowercase()
        return host.contains("android-build") || host == "buildbot" ||
               user == "android-build" || user == "buildbot" || user == "root"
    }

    private fun checkEmulatorPhoneNumber(context: Context): Boolean {
        if (context.checkSelfPermission(android.Manifest.permission.READ_PHONE_STATE)
            != android.content.pm.PackageManager.PERMISSION_GRANTED) return false
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            val number = tm.line1Number ?: return false
            listOf("15555215554", "15555215556", "15555215558", "15555215560",
                   "15555215562", "15555215564", "15555215566", "15555215568",
                   "15555215570", "15555215572").any { number.contains(it) }
        } catch (e: Exception) { false }
    }

    fun scan(context: Context, props: String): DetectorResult {
        val sm          = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val sensorCount = sm.getSensorList(Sensor.TYPE_ALL).size
        val hw          = Build.HARDWARE.lowercase()
        val radio       = Build.getRadioVersion()
        val ttyDrivers  = try { File("/proc/tty/drivers").readText() } catch (e: Exception) { "" }

        // Compute all checks once
        val qemu        = props.contains("ro.kernel.qemu]: [1]")
        val x86Abi      = Build.SUPPORTED_ABIS.any { it.contains("x86") }
        val genericFp   = Build.FINGERPRINT.contains("generic", true)
        val goldfishHw  = hw.contains("goldfish") || hw.contains("ranchu")
        val modelProd   = checkEmulatorModelOrProduct()
        val qemuFiles   = File("/dev/qemu_pipe").exists() || File("/dev/socket/qemud").exists()
        val emptyRadio  = radio.isNullOrEmpty() || radio == Build.UNKNOWN
        val goldfishTty = ttyDrivers.contains("goldfish", true)
        val blueStacks  = checkBlueStacks()
        val nox         = checkNox()
        val ldPlayer    = checkLDPlayer()
        val hostUser    = checkSuspiciousHostUser()
        val codename    = Build.VERSION.CODENAME != "REL"
        val lowSensor   = sensorCount < 4
        val emuPhone    = checkEmulatorPhoneNumber(context)

        val signals = listOf(
            Signal(SignalCategory.EMULATOR, "ro.kernel.qemu = 1 (QEMU detected)",         "ro.kernel.qemu not set",              4, qemu),
            Signal(SignalCategory.EMULATOR, "ABI is x86 (emulator pattern)",              "ABI is ARM (real device)",            2, x86Abi),
            Signal(SignalCategory.EMULATOR, "FINGERPRINT contains 'generic'",             "FINGERPRINT looks like real device",  2, genericFp),
            Signal(SignalCategory.EMULATOR, "Hardware: goldfish / ranchu",                "Hardware is not emulator chipset",    4, goldfishHw),
            Signal(SignalCategory.EMULATOR, "MODEL / PRODUCT matches emulator pattern",   "MODEL / PRODUCT looks normal",        3, modelProd),
            Signal(SignalCategory.EMULATOR, "QEMU device files found (/dev/qemu_pipe)",   "QEMU device files not found",         3, qemuFiles),
            Signal(SignalCategory.EMULATOR, "Build.RADIO is unknown / empty",             "Build.RADIO has real value",          2, emptyRadio),
            Signal(SignalCategory.EMULATOR, "/proc/tty/drivers contains 'goldfish'",      "/proc/tty/drivers looks normal",      2, goldfishTty),
            Signal(SignalCategory.EMULATOR, "BlueStacks detected",                        "BlueStacks not detected",             4, blueStacks),
            Signal(SignalCategory.EMULATOR, "Nox emulator detected",                      "Nox not detected",                    4, nox),
            Signal(SignalCategory.EMULATOR, "LDPlayer emulator detected",                 "LDPlayer not detected",               4, ldPlayer),
            Signal(SignalCategory.EMULATOR, "Suspicious Build.HOST / USER",               "Build.HOST / USER look normal",       2, hostUser),
            Signal(SignalCategory.EMULATOR, "Build.CODENAME is not REL",                 "Build.CODENAME is REL",               2, codename),
            Signal(SignalCategory.EMULATOR, "Sensor count < 4 (emulator pattern)",       "Sensor count looks normal ($sensorCount)", 2, lowSensor),
            Signal(SignalCategory.EMULATOR, "Emulator phone number detected",             "Phone number looks normal",           3, emuPhone),
        )

        val phoneNumber = if (context.checkSelfPermission(android.Manifest.permission.READ_PHONE_STATE)
            == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            try {
                val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
                tm.line1Number ?: "null"
            } catch (e: Exception) { "unavailable" }
        } else "permission denied"
        val qemuLine = props.lines().firstOrNull { it.contains("ro.kernel.qemu") }?.trim()
                       ?: "[ro.kernel.qemu]: (not found)"

        val rawData = listOf(
            "HARDWARE"              to Build.HARDWARE,
            "FINGERPRINT"           to Build.FINGERPRINT,
            "SUPPORTED_ABIS"        to Build.SUPPORTED_ABIS.joinToString(),
            "MODEL"                 to Build.MODEL,
            "PRODUCT"               to Build.PRODUCT,
            "TAGS"                  to Build.TAGS,
            "CODENAME"              to Build.VERSION.CODENAME,
            "RADIO"                 to (Build.getRadioVersion() ?: "null"),
            "HOST"                  to Build.HOST,
            "USER"                  to Build.USER,
            "BRAND"                 to Build.BRAND,
            "MANUFACTURER"          to Build.MANUFACTURER,
            "/dev/qemu_pipe"        to File("/dev/qemu_pipe").exists().toString(),
            "/dev/socket/qemud"     to File("/dev/socket/qemud").exists().toString(),
            "/data/bluestacks.prop" to File("/data/bluestacks.prop").exists().toString(),
            "/data/nox.prop"        to File("/data/nox.prop").exists().toString(),
            "Sensor count"          to sensorCount.toString(),
            "Line1 number"          to phoneNumber,
        ).joinToString("\n") { "${it.first}: ${it.second}" } +
            "\n\n$qemuLine" +
            "\n\n=== /proc/tty/drivers ===\n$ttyDrivers"

        return DetectorResult(signals, rawData)
    }
}
