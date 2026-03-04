package com.example.myapplication

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.example.myapplication.ui.theme.MyApplicationTheme
import java.io.File

data class Signal(
    val name: String,
    val weight: Int,
    val triggered: Boolean
)

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

fun checkSuPaths(): String {
    val paths = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/adb/magisk"
    )

    val results = paths.map { path ->
        "$path : ${File(path).exists()}"
    }

    return """
        ===== Root File Check =====
        ${results.joinToString("\n")}
    """.trimIndent()
}

fun readProcFile(path: String): String {
    return try {
        File(path).readText()
    } catch (e: Exception) {
        "Failed to read $path : ${e.message}"
    }
}

fun collectProcInfo(): String {
    val cpuInfo = readProcFile("/proc/cpuinfo")
    val memInfo = readProcFile("/proc/meminfo")
    val version = readProcFile("/proc/version")

    return """
        ===== /proc/cpuinfo =====
        $cpuInfo

        ===== /proc/meminfo =====
        $memInfo

        ===== /proc/version =====
        $version
    """.trimIndent()
}

@Composable
fun SectionCard(title: String, content: String, titleColor: Color = Color.Unspecified) {
    Spacer(modifier = Modifier.height(12.dp))

    Card {
        Column(modifier = Modifier.padding(16.dp)) {

            Text(
                text = title,
                color = titleColor,
                style = MaterialTheme.typography.titleMedium
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = content,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

@Composable
fun DeviceInfoScreen() {

    val props = collectSystemProperties()
    val score = calculateEmulatorScore(props)
    val signals = collectSuspiciousSignals(props)
    val scoreColor = when {
        score >= 6 -> Color.Red          // 위험
        score >= 3 -> Color(0xFFFF9800)  // 주황 (의심)
        else -> Color(0xFF4CAF50)        // 초록 (정상)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        SectionCard(
            title = "Suspicious Signals (Score: $score)",
            content = signals,
            titleColor = scoreColor
        )

        SectionCard(
            title = "Build Info",
            content = collectBuildInfo()
        )

        SectionCard(
            title = "System Properties (getprop)",
            content = props
        )

        SectionCard(
            title = "/proc Information",
            content = collectProcInfo()
        )

        SectionCard(
            title = "Root File Check",
            content = checkSuPaths()
        )
    }
}

fun calculateEmulatorScore(props: String): Int {
    var score = 0

    if (Build.FINGERPRINT.contains("generic", true)) score += 2
    if (Build.TAGS.contains("test-keys", true)) score += 1
    if (Build.SUPPORTED_ABIS.any { it.contains("x86") }) score += 2

    if (props.contains("ro.kernel.qemu]: [1]")) score += 4

    return score
}

fun collectSuspiciousSignals(props: String): String {
    val signals = mutableListOf<String>()

    if (Build.FINGERPRINT.contains("generic", true))
        signals.add("FINGERPRINT contains 'generic'")

    if (Build.TAGS.contains("test-keys", true))
        signals.add("Build TAGS contains 'test-keys'")

    if (Build.SUPPORTED_ABIS.any { it.contains("x86") })
        signals.add("ABI contains x86")

    if (collectSystemProperties().contains("ro.kernel.qemu]: [1]"))
        signals.add("ro.kernel.qemu = 1")

    return if (signals.isEmpty())
        "No suspicious signals detected"
    else
        signals.joinToString("\n")
}

fun collectBuildInfo(): String {
    return """
        ===== Build Info =====
        MODEL: ${Build.MODEL}
        BRAND: ${Build.BRAND}
        MANUFACTURER: ${Build.MANUFACTURER}
        DEVICE: ${Build.DEVICE}
        PRODUCT: ${Build.PRODUCT}
        HARDWARE: ${Build.HARDWARE}
        FINGERPRINT: ${Build.FINGERPRINT}
        TAGS: ${Build.TAGS}
        TYPE: ${Build.TYPE}
        BOOTLOADER: ${Build.BOOTLOADER}
        SUPPORTED_ABIS: ${Build.SUPPORTED_ABIS.joinToString()}
    """.trimIndent()
}

fun collectSystemProperties(): String {
    return try {
        val process = Runtime.getRuntime().exec("getprop")
        process.inputStream.bufferedReader().readText()
    } catch (e: Exception) {
        "getprop read failed: ${e.message}"
    }
}