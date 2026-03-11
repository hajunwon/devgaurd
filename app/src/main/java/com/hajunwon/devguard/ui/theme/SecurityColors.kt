package com.hajunwon.devguard.ui.theme

import androidx.compose.ui.graphics.Color
import com.hajunwon.devguard.data.model.SignalCategory
import com.hajunwon.devguard.data.model.SignalLayer

object SecurityColors {
    val emulator  = Color(0xFFEF5350)
    val root      = Color(0xFFFF5722)
    val debug     = Color(0xFFFF9800)
    val integrity = Color(0xFF9C27B0)
    val safe      = Color(0xFF4CAF50)

    // Detection layer colours — ordered by bypass difficulty (easiest → hardest)
    val layerJava    = Color(0xFF42A5F5) // blue   — hookable by Xposed / LSPosed
    val layerJni     = Color(0xFFFF7043) // orange — hookable by Frida / Dobby
    val layerSyscall = Color(0xFFEC407A) // pink   — only kernel-level hooks can bypass

    fun forCategory(category: SignalCategory): Color = when (category) {
        SignalCategory.EMULATOR  -> emulator
        SignalCategory.ROOT      -> root
        SignalCategory.DEBUG     -> debug
        SignalCategory.INTEGRITY -> integrity
    }

    fun forLayer(layer: SignalLayer): Color = when (layer) {
        SignalLayer.JAVA    -> layerJava
        SignalLayer.JNI     -> layerJni
        SignalLayer.SYSCALL -> layerSyscall
    }
}
