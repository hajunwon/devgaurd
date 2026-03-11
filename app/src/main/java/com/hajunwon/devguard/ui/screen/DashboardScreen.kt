package com.hajunwon.devguard.ui.screen

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import com.hajunwon.devguard.data.model.SignalLayer
import com.hajunwon.devguard.ui.LocalLanguage
import com.hajunwon.devguard.ui.component.RiskBadge
import com.hajunwon.devguard.ui.component.ShimmerCard
import com.hajunwon.devguard.ui.theme.SecurityColors
import com.hajunwon.devguard.ui.viewmodel.SecurityViewModel

// ── Device assessment ─────────────────────────────────────────────────────────

private data class Verdict(val label: String, val detail: String, val color: Color)

private fun buildVerdicts(signals: List<Signal>, isKo: Boolean): List<Verdict> {
    val t = signals.filter { it.triggered }
    if (t.isEmpty()) return emptyList()
    val result = mutableListOf<Verdict>()

    // 1. Active evasion — highest priority
    if (t.any { it.detectedText.startsWith("[Mismatch]") }) {
        result += Verdict(
            label  = if (isKo) "활성 회피 탐지됨" else "Active Evasion Detected",
            detail = if (isKo) "탐지 레이어 간 불일치 — 훅이 증거를 실시간으로 숨기는 중"
                     else       "Layer mismatch — a hook is hiding evidence in real time",
            color  = Color(0xFFB71C1C),
        )
    }

    // 2. Process injection — Frida/hook SO is loaded INTO this process
    //    Distinguished from "Frida server running on device" (checked in section 5)
    val injectionItems = buildList {
        if (t.any { "Frida" in it.detectedText && "maps" in it.detectedText.lowercase() })
            add(if (isKo) "Frida (프로세스에 인젝션됨)" else "Frida (injected into process)")
        if (t.any { "Frida server file" in it.detectedText })
            add(if (isKo) "Frida 스테이징 파일 탐지됨" else "Frida staging file detected")
        if (t.any { "staging" in it.detectedText && "Frida server file" !in it.detectedText })
            add(if (isKo) "Frida Gadget (스테이징 경로에서 로드)" else "Frida Gadget (loaded from staging path)")
        if (t.any { "inline-patched" in it.detectedText })
            add(if (isKo) "libc 인라인 훅 (Dobby/Frida)" else "libc inline hook (Dobby/Frida)")
        if (t.any { "Hook lib" in it.detectedText || "Hook/inject" in it.detectedText || "Hook .so" in it.detectedText })
            add(if (isKo) "Hook SO 로드됨" else "Hook SO loaded")
        if (t.any { "Substrate" in it.detectedText }) add("Cydia Substrate")
    }
    if (injectionItems.isNotEmpty()) {
        result += Verdict(
            label  = if (isKo) "프로세스 인젝션 감지됨" else "Process Injection Detected",
            detail = injectionItems.joinToString(" · "),
            color  = Color(0xFFD32F2F),
        )
    }

    // 3. Emulator / virtual environment — identify specific type
    if (t.any { it.category == SignalCategory.EMULATOR }) {
        val emuTypes = buildList {
            if (t.any { "BlueStacks" in it.detectedText }) add("BlueStacks")
            if (t.any { "Nox" in it.detectedText }) add("Nox")
            if (t.any { "LDPlayer" in it.detectedText }) add("LDPlayer")
            if (t.any { "Genymotion" in it.detectedText }) add("Genymotion")
            if (t.any { "MEmu" in it.detectedText || "MicroVirt" in it.detectedText }) add("MEmu")
            if (t.any { "WSA" in it.detectedText || "Windows Subsystem" in it.detectedText }) add("WSA")
            if (t.any { "QEMU" in it.detectedText || "goldfish" in it.detectedText.lowercase() || "ranchu" in it.detectedText.lowercase() }) add("Android AVD/QEMU")
            if (t.any { "x86" in it.detectedText.lowercase() && it.category == SignalCategory.EMULATOR }) add("x86 ABI")
        }
        result += Verdict(
            label  = if (isKo) "에뮬레이터 / 가상 환경" else "Emulator / Virtual Environment",
            detail = if (emuTypes.isNotEmpty()) emuTypes.joinToString(" · ")
                     else if (isKo) "가상 환경에서 실행 중" else "Running in virtual environment",
            color  = SecurityColors.emulator,
        )
    }

    // 4. Root — identify specific tools
    //    Note: "userdebug/eng build type" is a ROOT-category signal (not DEBUG)
    val rootSignals = t.filter { it.category == SignalCategory.ROOT }
    if (rootSignals.isNotEmpty()) {
        val tools = buildList {
            if (rootSignals.any { "Magisk" in it.detectedText }) add("Magisk")
            if (rootSignals.any { "KernelSU" in it.detectedText }) add("KernelSU")
            if (rootSignals.any { "APatch" in it.detectedText }) add("APatch")
            if (rootSignals.any { "Shamiko" in it.detectedText }) add("Shamiko")
            if (rootSignals.any { "Zygisk" in it.detectedText }) add("Zygisk")
            if (rootSignals.any { "Riru" in it.detectedText }) add("Riru")
            if (rootSignals.any { "Xposed" in it.detectedText || "LSPosed" in it.detectedText }) add("Xposed/LSPosed")
            if (rootSignals.any { "su binary" in it.detectedText || "su command" in it.detectedText })
                add(if (isKo) "su 바이너리" else "su binary")
            if (rootSignals.any { "Bootloader unlocked" in it.detectedText })
                add(if (isKo) "부트로더 잠금 해제" else "Bootloader unlocked")
            if (rootSignals.any { "overlay mounts" in it.detectedText || "Suspicious mounts" in it.detectedText })
                add(if (isKo) "Magisk 마운트 흔적" else "Magisk mount traces")
            if (rootSignals.any { "userdebug" in it.detectedText || "eng" in it.detectedText })
                add(if (isKo) "개발자 빌드 ROM" else "Developer build ROM")
            if (rootSignals.any { "ADB root" in it.detectedText })
                add(if (isKo) "ADB 루트 활성" else "ADB root active")
        }
        result += Verdict(
            label  = if (isKo) "루팅됨" else "Rooted",
            detail = if (tools.isNotEmpty()) tools.joinToString(" · ")
                     else if (isKo) "루팅 징후 감지됨" else "Root indicators detected",
            color  = SecurityColors.root,
        )
    }

    // 5. Frida server / debugger running on device (not necessarily injected into this process)
    val debugSignals = t.filter { it.category == SignalCategory.DEBUG }
    if (debugSignals.isNotEmpty()) {
        val items = buildList {
            // Debugger attached check — signal text is "Debugger attached (isDebuggerConnected)"
            if (debugSignals.any { "Debugger attached" in it.detectedText })
                add(if (isKo) "디버거 연결됨" else "Debugger attached")
            // TracerPid != 0 — signal text is "TracerPid ≠ 0 (process being traced)"
            if (debugSignals.any { "TracerPid" in it.detectedText }) add("TracerPid ≠ 0")
            // ptrace self-check — signal text is "[JNI] ptrace self-check (PTRACE_TRACEME)"
            if (debugSignals.any { "ptrace" in it.detectedText.lowercase() })
                add(if (isKo) "ptrace 감지" else "ptrace detected")
            // Frida server signals — "Frida server detected (port …)", "Frida process found in /proc", etc.
            if (debugSignals.any { "Frida" in it.detectedText })
                add(if (isKo) "Frida 서버/프로세스 실행 중" else "Frida server/process running")
            if (debugSignals.any { "gdbserver" in it.detectedText })
                add(if (isKo) "gdbserver 실행 중" else "gdbserver running")
            if (debugSignals.any { "JDWP" in it.detectedText })
                add(if (isKo) "JDWP 디버거 포트 열림" else "JDWP debugger port open")
            if (debugSignals.any { "USB debugging" in it.detectedText })
                add(if (isKo) "USB 디버깅 활성" else "USB debugging enabled")
            if (debugSignals.any { "Developer options" in it.detectedText })
                add(if (isKo) "개발자 옵션 활성" else "Developer options enabled")
        }
        result += Verdict(
            label  = if (isKo) "디버그 / 분석 환경" else "Debug / Analysis Environment",
            detail = items.joinToString(" · ").ifEmpty { if (isKo) "디버그 환경 감지됨" else "Debug environment detected" },
            color  = SecurityColors.debug,
        )
    }

    // 6. MITM / traffic interception
    //    "HTTP proxy configured" signal is in DEBUG category
    if (t.any { "HTTP proxy" in it.detectedText }) {
        result += Verdict(
            label  = if (isKo) "트래픽 분석 환경 (MITM)" else "Traffic Interception (MITM)",
            detail = if (isKo) "HTTP 프록시 설정됨 — Burp Suite / Charles 등 가능"
                     else       "HTTP proxy configured — Burp Suite / Charles etc.",
            color  = SecurityColors.debug,
        )
    }

    // 7. Integrity issues
    val intSignals = t.filter { it.category == SignalCategory.INTEGRITY }
    if (intSignals.isNotEmpty()) {
        val items = buildList {
            if (intSignals.any { "SELinux" in it.detectedText })
                add(if (isKo) "SELinux 비활성화" else "SELinux disabled")
            if (intSignals.any { "debug certificate" in it.detectedText })
                add(if (isKo) "디버그 서명 APK" else "Debug-signed APK")
            if (intSignals.any { "Play Store" in it.detectedText })
                add(if (isKo) "비공식 경로 설치" else "Installed from unofficial source")
            if (intSignals.any { "Root/hook app" in it.detectedText })
                add(if (isKo) "루트/훅 앱 설치됨" else "Root/hook apps installed")
            if (intSignals.any { "cert" in it.detectedText.lowercase() && "match" in it.detectedText.lowercase() })
                add(if (isKo) "인증서 불일치 (재패키징 의심)" else "Certificate mismatch (repackaging suspected)")
        }
        result += Verdict(
            label  = if (isKo) "무결성 문제" else "Integrity Issues",
            detail = items.joinToString(" · ").ifEmpty { if (isKo) "무결성 이상 감지됨" else "Integrity anomaly detected" },
            color  = SecurityColors.integrity,
        )
    }

    return result
}

@Composable
private fun AllClearCard() {
    val isKo = LocalLanguage.current == "ko"
    ElevatedCard(
        shape    = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth(),
        colors   = CardDefaults.elevatedCardColors(
            containerColor = SecurityColors.safe.copy(alpha = 0.08f)
        ),
    ) {
        Row(
            modifier              = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 18.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment     = Alignment.CenterVertically,
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier         = Modifier
                    .size(48.dp)
                    .background(SecurityColors.safe.copy(alpha = 0.18f), CircleShape),
            ) {
                Text(
                    text  = "✓",
                    style = MaterialTheme.typography.titleLarge,
                    color = SecurityColors.safe,
                )
            }
            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(
                    text       = if (isKo) "기기가 안전합니다" else "Device is Clean",
                    style      = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color      = SecurityColors.safe,
                )
                Text(
                    text  = if (isKo) "탐지된 위협 신호가 없습니다"
                            else       "No threat signals detected",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun AssessmentCard(signals: List<Signal>) {
    val isKo     = LocalLanguage.current == "ko"
    val verdicts = remember(signals, isKo) { buildVerdicts(signals, isKo) }
    if (verdicts.isEmpty()) {
        AllClearCard()
        return
    }

    ElevatedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp)) {
            Text(
                text     = if (isKo) "기기 평가" else "Device Assessment",
                style    = MaterialTheme.typography.labelSmall,
                color    = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 10.dp),
            )
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                verdicts.forEach { verdict ->
                    Row(
                        modifier              = Modifier
                            .fillMaxWidth()
                            .height(IntrinsicSize.Min),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment     = Alignment.Top,
                    ) {
                        // Left accent bar
                        Box(
                            Modifier
                                .width(3.dp)
                                .fillMaxHeight()
                                .clip(RoundedCornerShape(2.dp))
                                .background(verdict.color)
                        )
                        Column(
                            modifier            = Modifier.padding(vertical = 2.dp),
                            verticalArrangement = Arrangement.spacedBy(2.dp),
                        ) {
                            Text(
                                text       = verdict.label,
                                style      = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold,
                                color      = verdict.color,
                            )
                            Text(
                                text  = verdict.detail,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}

// ── Layer count summary ───────────────────────────────────────────────────────

@Composable
private fun LayerCountItem(label: String, count: Int, color: Color) {
    val chipColor = if (count > 0) color else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f)
    Row(
        verticalAlignment     = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = chipColor)
        Surface(
            shape = RoundedCornerShape(4.dp),
            color = chipColor.copy(alpha = if (count > 0) 0.15f else 0.07f),
        ) {
            Text(
                text       = count.toString(),
                modifier   = Modifier.padding(horizontal = 5.dp, vertical = 1.dp),
                style      = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color      = chipColor,
            )
        }
    }
}

@Composable
private fun LayerCountCard(signals: List<Signal>) {
    val isKo         = LocalLanguage.current == "ko"
    val triggered    = signals.filter { it.triggered }
    val javaCount    = triggered.count { it.layer == SignalLayer.JAVA }
    val jniCount     = triggered.count { it.layer == SignalLayer.JNI }
    val syscallCount = triggered.count { it.layer == SignalLayer.SYSCALL }
    val totalCount   = triggered.size

    ElevatedCard(shape = RoundedCornerShape(12.dp)) {
        Column(
            modifier            = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Text(
                text       = if (totalCount > 0)
                                 if (isKo) "위협 신호 $totalCount 개 탐지됨"
                                 else "$totalCount threat signal${if (totalCount != 1) "s" else ""} detected"
                             else
                                 if (isKo) "위협 없음" else "No threats detected",
                style      = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color      = if (totalCount > 0) Color(0xFFD32F2F) else SecurityColors.safe,
            )
            Row(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment     = Alignment.CenterVertically,
            ) {
                LayerCountItem("API", javaCount,    SecurityColors.layerJava)
                Text("·", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
                LayerCountItem("JNI", jniCount,     SecurityColors.layerJni)
                Text("·", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
                LayerCountItem("SYS", syscallCount, SecurityColors.layerSyscall)
            }
        }
    }
}

// ── Category summary ──────────────────────────────────────────────────────────

@Composable
private fun CategorySummaryRow(category: SignalCategory, signals: List<Signal>) {
    val isKo      = LocalLanguage.current == "ko"
    val triggered = signals.filter { it.triggered }
    val color     = if (triggered.isNotEmpty()) SecurityColors.forCategory(category) else SecurityColors.safe

    Row(
        modifier              = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.CenterVertically,
    ) {
        Text(
            text       = if (isKo) category.displayNameKo else category.displayName,
            style      = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
            color      = color,
        )
        if (triggered.isNotEmpty()) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                verticalAlignment     = Alignment.CenterVertically,
            ) {
                SignalLayer.entries.forEach { layer ->
                    val cnt = triggered.count { it.layer == layer }
                    if (cnt > 0) {
                        val layerColor = SecurityColors.forLayer(layer)
                        val layerLabel = when (layer) {
                            SignalLayer.JAVA    -> "API"
                            SignalLayer.JNI     -> "JNI"
                            SignalLayer.SYSCALL -> "SYS"
                        }
                        Surface(
                            shape  = RoundedCornerShape(3.dp),
                            color  = layerColor.copy(alpha = 0.13f),
                            border = BorderStroke(0.5.dp, layerColor.copy(alpha = 0.4f)),
                        ) {
                            Text(
                                text     = "$layerLabel $cnt",
                                modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
                                style    = MaterialTheme.typography.labelSmall,
                                color    = layerColor,
                                fontSize = 9.sp,
                            )
                        }
                    }
                }
            }
        } else {
            Text(
                text  = if (isKo) "✓ 안전" else "✓ Clean",
                style = MaterialTheme.typography.labelSmall,
                color = color.copy(alpha = 0.8f),
            )
        }
    }
}

@Composable
private fun CategorySummaryCard(signals: List<Signal>) {
    ElevatedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            SignalCategory.entries.forEachIndexed { idx, cat ->
                if (idx > 0) {
                    HorizontalDivider(
                        thickness = 0.5.dp,
                        color     = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                        modifier  = Modifier.padding(vertical = 2.dp),
                    )
                }
                CategorySummaryRow(cat, signals.filter { it.category == cat })
            }
        }
    }
}

// ── Layer mismatch warning ────────────────────────────────────────────────────

@Composable
private fun LayerMismatchCard(signals: List<Signal>) {
    val isKo       = LocalLanguage.current == "ko"
    val mismatches = signals.filter { it.triggered && it.detectedText.startsWith("[Mismatch]") }
    if (mismatches.isEmpty()) return

    val warnColor = Color(0xFFB71C1C)
    ElevatedCard(
        shape  = RoundedCornerShape(16.dp),
        colors = CardDefaults.elevatedCardColors(containerColor = warnColor.copy(alpha = 0.08f)),
    ) {
        Column(
            modifier            = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text       = if (isKo) "⚠ 레이어 불일치 — 활성 회피 의심"
                             else       "⚠ Layer Mismatch — Active Evasion Suspected",
                style      = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color      = warnColor,
            )
            Text(
                text  = if (isKo) "탐지 레이어 간 결과가 다릅니다. 훅이 상위 레이어에서 증거를 숨기는 중일 수 있습니다."
                        else       "Detection layers disagree. A hook is likely hiding evidence from higher layers.",
                style = MaterialTheme.typography.bodySmall,
                color = warnColor.copy(alpha = 0.85f),
            )
            mismatches.forEach { sig ->
                Text(
                    text  = "• ${sig.detectedText.removePrefix("[Mismatch] ")}",
                    style = MaterialTheme.typography.bodySmall,
                    color = warnColor,
                )
            }
        }
    }
}

// ── Main screen ───────────────────────────────────────────────────────────────

private fun localizeRiskLevel(label: String, subtitle: String, isKo: Boolean): Pair<String, String> {
    if (!isKo) return label to subtitle
    val labelKo = when (label) {
        "COMPROMISED" -> "위험"
        "EMULATOR"    -> "에뮬레이터"
        "HIGH RISK"   -> "고위험"
        "SUSPICIOUS"  -> "의심"
        "LOW RISK"    -> "경고"
        "CLEAN"       -> "안전"
        else          -> label
    }
    val subtitleKo = when (subtitle) {
        "Active evasion detected"       -> "활성 회피 탐지됨"
        "Heavily modified environment"  -> "심각하게 변조된 환경"
        "Likely an emulator"            -> "에뮬레이터일 가능성 높음"
        "Rooted or modified device"     -> "루팅 또는 변조된 기기"
        "Risk signals detected"         -> "위험 신호 감지됨"
        "Minor signals detected"        -> "경미한 신호 감지됨"
        "No suspicious signals"         -> "의심스러운 신호 없음"
        else                            -> subtitle
    }
    return labelKo to subtitleKo
}

@Composable
fun DashboardScreen(viewModel: SecurityViewModel) {
    val state by viewModel.uiState.collectAsState()

    if (state.isLoading) {
        val shimmerTransition = rememberInfiniteTransition(label = "shimmer")
        val shimmerX by shimmerTransition.animateFloat(
            initialValue  = -600f,
            targetValue   =  600f,
            animationSpec = infiniteRepeatable(
                animation  = tween(1000, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "shimmerX"
        )
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            ShimmerCard(height = 200.dp, translateX = shimmerX)
            ShimmerCard(height = 120.dp, translateX = shimmerX)
            ShimmerCard(height = 60.dp,  translateX = shimmerX)
            ShimmerCard(height = 130.dp, translateX = shimmerX)
            Spacer(Modifier.height(80.dp))
        }
        return
    }

    val isKo = LocalLanguage.current == "ko"
    val (riskLabel, riskSubtitle) = remember(state.riskLevel, isKo) {
        localizeRiskLevel(state.riskLevel.label, state.riskLevel.subtitle, isKo)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Overall risk score
        RiskBadge(
            label    = riskLabel,
            subtitle = riskSubtitle,
            score    = state.score,
            maxScore = state.maxScore,
            color    = remember(state.riskLevel.colorArgb) { Color(state.riskLevel.colorArgb) }
        )

        // Active evasion warning — highest priority, shown immediately under score
        LayerMismatchCard(state.signals)

        // Human-readable verdict — what was actually found on this device
        AssessmentCard(state.signals)

        // Technical layer count breakdown
        LayerCountCard(state.signals)

        // Per-category pass/fail summary
        CategorySummaryCard(state.signals)

        Spacer(Modifier.height(80.dp))
    }
}
