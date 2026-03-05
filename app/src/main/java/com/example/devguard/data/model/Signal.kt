package com.example.devguard.data.model

import androidx.compose.ui.graphics.Color

enum class SignalCategory(val displayName: String) {
    EMULATOR("Emulator Detection"),
    ROOT("Root Detection"),
    DEBUG("Debug & Hooking"),
    INTEGRITY("App Integrity")
}

data class Signal(
    val category: SignalCategory,
    val detectedText: String,
    val passText: String,
    val weight: Int,
    val triggered: Boolean
)

data class RiskLevel(val label: String, val subtitle: String, val color: Color)

data class DetectorResult(val signals: List<Signal>, val rawData: String)
