package com.hajunwon.devguard.domain

import android.content.Context
import androidx.compose.ui.graphics.Color
import com.hajunwon.devguard.data.detector.DebugDetector
import com.hajunwon.devguard.data.detector.EmulatorDetector
import com.hajunwon.devguard.data.detector.IntegrityDetector
import com.hajunwon.devguard.data.detector.RootDetector
import com.hajunwon.devguard.data.model.RiskLevel
import com.hajunwon.devguard.data.model.Signal
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

data class FullScanResult(
    val signals: List<Signal>,
    val score: Int,
    val riskLevel: RiskLevel,
    val emulatorRaw: String,
    val rootRaw: String,
    val debugRaw: String,
    val integrityRaw: String,
)

object SecurityAnalyzer {

    suspend fun fullScan(context: Context, props: String): FullScanResult = coroutineScope {
        // Run all 4 detectors in parallel
        val emulatorDeferred  = async { EmulatorDetector.scan(context, props) }
        val rootDeferred      = async { RootDetector.scan(props) }
        val debugDeferred     = async { DebugDetector.scan(context) }
        val integrityDeferred = async { IntegrityDetector.scan(context) }

        val emulator  = emulatorDeferred.await()
        val root      = rootDeferred.await()
        val debug     = debugDeferred.await()
        val integrity = integrityDeferred.await()

        val signals = emulator.signals + root.signals + debug.signals + integrity.signals
        val score   = calculateScore(signals)
        FullScanResult(
            signals      = signals,
            score        = score,
            riskLevel    = getRiskLevel(score),
            emulatorRaw  = emulator.rawData,
            rootRaw      = root.rawData,
            debugRaw     = debug.rawData,
            integrityRaw = integrity.rawData,
        )
    }

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
}
