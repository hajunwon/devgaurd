package com.hajunwon.devguard.data.model

enum class SignalCategory(val displayName: String, val displayNameKo: String) {
    EMULATOR("Emulator Detection", "에뮬레이터 탐지"),
    ROOT    ("Root Detection",     "루팅 탐지"),
    DEBUG   ("Debug & Hooking",    "디버그 / 훅"),
    INTEGRITY("App Integrity",     "앱 무결성"),
}

enum class SignalLayer {
    JAVA,    // Standard Android API  — hookable by Xposed / LSPosed
    JNI,     // C++ via libc calls    — hookable by Frida / Dobby inline patch
    SYSCALL, // Direct kernel syscall — only kernel-level hooks can bypass
}

data class Signal(
    val category: SignalCategory,
    val detectedText: String,
    val passText: String,
    val weight: Int,
    val triggered: Boolean,
    val layer: SignalLayer = SignalLayer.JAVA,
    /**
     * Cross-layer deduplication key.
     * Signals with the same non-empty group detect the same underlying fact
     * across JVM / JNI / SYSCALL layers. The scoring engine takes the highest
     * single-layer weight and adds a corroboration bonus (+1 per extra confirming
     * layer, capped at +2) instead of summing all weights.
     * Leave empty ("") for signals that have no cross-layer counterpart.
     */
    val group: String = "",
)

/** colorArgb stores a packed 0xAARRGGBB Long — no Compose dependency in the data layer. */
data class RiskLevel(val label: String, val subtitle: String, val colorArgb: Long)

data class DetectorResult(val signals: List<Signal>, val rawData: String)
