package com.hajunwon.devguard.domain

import android.content.Context
import com.hajunwon.devguard.data.detector.DebugDetector
import com.hajunwon.devguard.data.detector.EmulatorDetector
import com.hajunwon.devguard.data.detector.IntegrityDetector
import com.hajunwon.devguard.data.detector.RootDetector
import com.hajunwon.devguard.data.model.RiskLevel
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

data class FullScanResult(
    val signals: List<Signal>,
    val score: Int,
    val maxPossibleScore: Int,
    val riskLevel: RiskLevel,
    val emulatorRaw: String,
    val rootRaw: String,
    val debugRaw: String,
    val integrityRaw: String,
)

object SecurityAnalyzer {

    /**
     * Maximum score contribution per category (sums to 100).
     *
     * ROOT has the highest cap because it has the most signals and represents
     * the highest security impact. INTEGRITY is narrow-scope (4 signals).
     * Mismatch signals (active evasion) bypass these caps intentionally.
     */
    private val CAT_CAPS = mapOf(
        SignalCategory.EMULATOR  to 28,
        SignalCategory.ROOT      to 42,
        SignalCategory.DEBUG     to 20,
        SignalCategory.INTEGRITY to 10,
    )

    suspend fun fullScan(context: Context, props: String): FullScanResult = coroutineScope {
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
            signals          = signals,
            score            = score,
            maxPossibleScore = 100,   // normalized reference: always 100
            riskLevel        = getRiskLevel(score, signals),
            emulatorRaw      = emulator.rawData,
            rootRaw          = root.rawData,
            debugRaw         = debug.rawData,
            integrityRaw     = integrity.rawData,
        )
    }

    /**
     * Group-aware, category-capped scoring algorithm. Returns 0–100.
     *
     * Design goals:
     *   1. Cross-layer deduplication — the same fact detected by JVM + JNI + SYSCALL
     *      counts once (max weight) plus a corroboration bonus, not three separate times.
     *   2. Category caps — prevent a signal-heavy category (ROOT, ~30 signals) from
     *      completely dominating the total score.
     *   3. Mismatch bypass — "[Mismatch]" signals indicate active evasion and are
     *      deliberately excluded from the category cap; they represent proof that the
     *      device is not just modified but is actively hiding the modification.
     *   4. Normalized 0–100 — intuitive "X / 100" display in the UI.
     */
    fun calculateScore(signals: List<Signal>): Int {
        val triggered = signals.filter { it.triggered }

        // Mismatch signals represent active in-process evasion — highest severity,
        // intentionally bypass category caps to ensure they always lift the total score.
        val mismatches = triggered.filter { it.detectedText.startsWith("[Mismatch]") }
        val regular    = triggered.filter { !it.detectedText.startsWith("[Mismatch]") }

        val categoryScore = SignalCategory.entries.sumOf { cat ->
            val catSignals = regular.filter { it.category == cat }

            // Named groups: deduplicate across layers.
            // Score = max_weight_in_group + min(extra_confirming_layers, 2)
            val namedGroupScore = catSignals
                .filter { it.group.isNotEmpty() }
                .groupBy { it.group }
                .values
                .sumOf { grp ->
                    grp.maxOf { it.weight } + (grp.size - 1).coerceIn(0, 2)
                }

            // Ungrouped signals have no cross-layer counterpart; count fully.
            val ungroupedScore = catSignals
                .filter { it.group.isEmpty() }
                .sumOf { it.weight }

            minOf(namedGroupScore + ungroupedScore, CAT_CAPS[cat] ?: Int.MAX_VALUE)
        }

        val mismatchScore = mismatches.sumOf { it.weight }
        return (categoryScore + mismatchScore).coerceAtMost(100)
    }

    /**
     * Contextual risk classification using both the normalized score and the
     * specific signals that triggered. This allows EMULATOR to be identified
     * even when the raw score overlaps with HIGH RISK, and COMPROMISED to be
     * called out specifically when active evasion is present.
     */
    fun getRiskLevel(score: Int, signals: List<Signal> = emptyList()): RiskLevel {
        val triggered    = signals.filter { it.triggered }
        val hasMismatch  = triggered.any { it.detectedText.startsWith("[Mismatch]") }
        val emulatorHits = triggered.count { it.category == SignalCategory.EMULATOR }

        return when {
            // Active evasion always escalates to COMPROMISED once evidence threshold met
            hasMismatch && score >= 20 ->
                RiskLevel("COMPROMISED", "Active evasion detected",       0xFFB71C1C)
            // Very high score even without mismatch = severely compromised
            score >= 60 ->
                RiskLevel("COMPROMISED", "Heavily modified environment",   0xFFB71C1C)
            // Emulator: require multiple corroborating signals, not just high score
            emulatorHits >= 5 || (emulatorHits >= 3 && score >= 22) ->
                RiskLevel("EMULATOR",    "Likely an emulator",             0xFFEF5350)
            score >= 24 ->
                RiskLevel("HIGH RISK",   "Rooted or modified device",      0xFFFF5722)
            score >= 11 ->
                RiskLevel("SUSPICIOUS",  "Risk signals detected",          0xFFFF9800)
            score >= 3  ->
                RiskLevel("LOW RISK",    "Minor signals detected",         0xFFFFC107)
            else ->
                RiskLevel("CLEAN",       "No suspicious signals",          0xFF4CAF50)
        }
    }
}
