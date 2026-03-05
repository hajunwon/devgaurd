package com.example.devguard.domain

import android.content.Context
import androidx.compose.ui.graphics.Color
import com.example.devguard.data.detector.DebugDetector
import com.example.devguard.data.detector.EmulatorDetector
import com.example.devguard.data.detector.IntegrityDetector
import com.example.devguard.data.detector.RootDetector
import com.example.devguard.data.model.RiskLevel
import com.example.devguard.data.model.Signal

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

    fun fullScan(context: Context, props: String): FullScanResult {
        val emulator  = EmulatorDetector.scan(context, props)
        val root      = RootDetector.scan(props)
        val debug     = DebugDetector.scan(context)
        val integrity = IntegrityDetector.scan(context)
        val signals   = emulator.signals + root.signals + debug.signals + integrity.signals
        val score     = calculateScore(signals)
        return FullScanResult(
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
