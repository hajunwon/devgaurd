package com.hajunwon.devguard.ui.screen

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.hajunwon.devguard.ui.LocalLanguage
import com.hajunwon.devguard.ui.component.CollapsibleInfoCard
import com.hajunwon.devguard.ui.component.ShimmerCard
import com.hajunwon.devguard.ui.viewmodel.SecurityViewModel

@Composable
fun RawScreen(viewModel: SecurityViewModel) {
    val state by viewModel.uiState.collectAsState()
    val isKo  = LocalLanguage.current == "ko"

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
            repeat(8) { ShimmerCard(height = 56.dp, translateX = shimmerX) }
            Spacer(Modifier.height(80.dp))
        }
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // ── Detection signal sources ───────────────────────────────────────────
        CollapsibleInfoCard(
            title   = if (isKo) "에뮬레이터 신호 원본" else "Emulator Signal Sources",
            content = state.emulatorRaw,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "루팅 신호 원본" else "Root Signal Sources",
            content = state.rootRaw,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "디버그 신호 원본" else "Debug Signal Sources",
            content = state.debugRaw,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "무결성 신호 원본" else "Integrity Signal Sources",
            content = state.integrityRaw,
        )

        // ── System info ────────────────────────────────────────────────────────
        CollapsibleInfoCard(
            title   = if (isKo) "빌드 정보" else "Build Info",
            content = state.buildInfo,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "디스플레이" else "Display Metrics",
            content = state.displayInfo,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "하드웨어 / 메모리" else "Hardware & Memory",
            content = state.hardwareInfo,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "배터리" else "Battery",
            content = state.batteryRaw,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "센서" else "Sensors",
            content = state.sensorInfo,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "네트워크" else "Network",
            content = state.networkInfo,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "식별자" else "Identifiers",
            content = state.identifiers,
        )
        CollapsibleInfoCard(
            title   = if (isKo) "시스템 속성" else "System Properties",
            content = state.props,
        )
        CollapsibleInfoCard(
            title   = "/proc Info",
            content = state.procInfo,
        )

        Spacer(Modifier.height(80.dp))
    }
}
