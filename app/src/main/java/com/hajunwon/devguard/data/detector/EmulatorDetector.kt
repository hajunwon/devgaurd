package com.hajunwon.devguard.data.detector

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.telephony.TelephonyManager
import com.hajunwon.devguard.data.model.DetectorResult
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import com.hajunwon.devguard.data.model.SignalLayer
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

    /**
     * Reads /sys/class/power_supply/battery/temp (unit: tenths of °C).
     * Real devices always report some non-zero temperature; emulators report exactly 0.
     */
    private fun checkBatteryTempIsZero(): Boolean = try {
        val raw = File("/sys/class/power_supply/battery/temp").readText().trim()
        raw.toIntOrNull() == 0
    } catch (e: Exception) { false }

    private fun checkGenymotion(): Boolean =
        Build.MANUFACTURER.lowercase().contains("genymobile") ||
        Build.FINGERPRINT.lowercase().contains("vbox86p") ||
        File("/dev/socket/genyd").exists() ||
        File("/dev/socket/baseband_genyd").exists()

    private fun checkMEmu(): Boolean =
        Build.MANUFACTURER.lowercase().contains("microvirt") ||
        File("/data/memu.prop").exists() ||
        File("/data/memu_share").exists()

    private fun checkWsa(): Boolean =
        Build.MANUFACTURER.lowercase().contains("microsoft") ||
        Build.PRODUCT.lowercase().contains("windows") ||
        Build.MODEL.contains("Subsystem for Android", ignoreCase = true) ||
        File("/mnt/windows_shared").exists()

    /**
     * Real devices always have both eth0 (or rmnet0) and wlan0.
     * Emulators typically expose only eth0 as the single virtual NIC.
     */
    private fun checkEmulatorNetworkInterface(): Boolean =
        File("/sys/class/net/eth0").exists() && !File("/sys/class/net/wlan0").exists()

    /**
     * Extra QEMU / goldfish kernel properties that are set on emulators
     * but absent on real hardware.
     */
    private fun checkAdditionalQemuProps(props: String): Boolean =
        props.contains("ro.kernel.android.qemud") ||
        props.contains("init.svc.goldfish-logcat") ||
        props.contains("ro.kernel.qemu.gles")

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
        val emuPhone      = checkEmulatorPhoneNumber(context)
        val battTempZero  = checkBatteryTempIsZero()
        val genymotion    = checkGenymotion()
        val memu          = checkMEmu()
        val wsa           = checkWsa()
        val ethNoWlan     = checkEmulatorNetworkInterface()
        val qemuExtraProps = checkAdditionalQemuProps(props)

        val jvmSignals = listOf(
            Signal(SignalCategory.EMULATOR, "ro.kernel.qemu = 1 (QEMU detected)",         "ro.kernel.qemu not set",              4, qemu,      group = "emu_qemu_prop"),
            Signal(SignalCategory.EMULATOR, "ABI is x86 (emulator pattern)",              "ABI is ARM (real device)",            2, x86Abi,    group = "emu_x86"),
            Signal(SignalCategory.EMULATOR, "FINGERPRINT contains 'generic'",             "FINGERPRINT looks like real device",  2, genericFp),
            Signal(SignalCategory.EMULATOR, "Hardware: goldfish / ranchu",                "Hardware is not emulator chipset",    4, goldfishHw),
            Signal(SignalCategory.EMULATOR, "MODEL / PRODUCT matches emulator pattern",   "MODEL / PRODUCT looks normal",        3, modelProd),
            Signal(SignalCategory.EMULATOR, "QEMU device files found (/dev/qemu_pipe)",   "QEMU device files not found",         3, qemuFiles, group = "emu_qemu_files"),
            Signal(SignalCategory.EMULATOR, "Build.RADIO is unknown / empty",             "Build.RADIO has real value",          2, emptyRadio),
            Signal(SignalCategory.EMULATOR, "/proc/tty/drivers contains 'goldfish'",      "/proc/tty/drivers looks normal",      2, goldfishTty),
            Signal(SignalCategory.EMULATOR, "BlueStacks detected",                        "BlueStacks not detected",             4, blueStacks),
            Signal(SignalCategory.EMULATOR, "Nox emulator detected",                      "Nox not detected",                    4, nox),
            Signal(SignalCategory.EMULATOR, "LDPlayer emulator detected",                 "LDPlayer not detected",               4, ldPlayer),
            Signal(SignalCategory.EMULATOR, "Suspicious Build.HOST / USER",               "Build.HOST / USER look normal",       2, hostUser),
            Signal(SignalCategory.EMULATOR, "Build.CODENAME is not REL",                 "Build.CODENAME is REL",               2, codename),
            Signal(SignalCategory.EMULATOR, "Sensor count < 4 (emulator pattern)",       "Sensor count looks normal ($sensorCount)", 2, lowSensor),
            Signal(SignalCategory.EMULATOR, "Emulator phone number detected",             "Phone number looks normal",           3, emuPhone),
            Signal(SignalCategory.EMULATOR, "Battery temperature = 0 (emulator pattern)", "Battery temperature > 0 (real device)", 2, battTempZero),
            Signal(SignalCategory.EMULATOR, "Genymotion emulator detected",              "Genymotion not detected",              4, genymotion),
            Signal(SignalCategory.EMULATOR, "MEmu (MicroVirt) emulator detected",        "MEmu not detected",                    4, memu),
            Signal(SignalCategory.EMULATOR, "Windows Subsystem for Android (WSA)",       "WSA not detected",                     4, wsa),
            Signal(SignalCategory.EMULATOR, "eth0 present / wlan0 absent (virtual NIC)", "Network interfaces look normal",       2, ethNoWlan),
            Signal(SignalCategory.EMULATOR, "Additional QEMU kernel props detected",     "No extra QEMU props",                  3, qemuExtraProps),
        )

        val jniSignals: List<Signal> = if (NativeDetector.isAvailable) listOf(
            Signal(SignalCategory.EMULATOR, "ro.kernel.qemu=1 (sysprop)",     "ro.kernel.qemu not set",    4, NativeDetector.nativeCheckQemuProp(),   SignalLayer.JNI,     "emu_qemu_prop"),
            Signal(SignalCategory.EMULATOR, "QEMU device files (stat)",       "QEMU files not found",      3, NativeDetector.nativeCheckQemuFiles(),  SignalLayer.JNI,     "emu_qemu_files"),
            Signal(SignalCategory.EMULATOR, "CPU ABI is x86 (sysprop)",       "CPU ABI is ARM",            2, NativeDetector.nativeCheckCpuIsX86(),   SignalLayer.JNI,     "emu_x86"),
        ) else emptyList()

        val syscallSignals: List<Signal> = if (NativeDetector.isAvailable) listOf(
            Signal(SignalCategory.EMULATOR, "QEMU device files (faccessat)",  "QEMU files not found",      3, NativeDetector.syscallCheckQemuFiles(), SignalLayer.SYSCALL, "emu_qemu_files"),
        ) else emptyList()

        val signals = jvmSignals + jniSignals + syscallSignals

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
            "Battery temp (raw)"       to (runCatching { File("/sys/class/power_supply/battery/temp").readText().trim() }.getOrDefault("unavailable")),
            "/dev/socket/genyd"        to File("/dev/socket/genyd").exists().toString(),
            "/sys/class/net/eth0"      to File("/sys/class/net/eth0").exists().toString(),
            "/sys/class/net/wlan0"     to File("/sys/class/net/wlan0").exists().toString(),
        ).joinToString("\n") { "${it.first}: ${it.second}" } +
            "\n\n$qemuLine" +
            "\n\n=== /proc/tty/drivers ===\n$ttyDrivers"

        return DetectorResult(signals, rawData)
    }
}
