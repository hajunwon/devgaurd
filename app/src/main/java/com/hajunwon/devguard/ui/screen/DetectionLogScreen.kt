package com.hajunwon.devguard.ui.screen

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.OutlinedButton
import com.hajunwon.devguard.data.model.SignalCategory
import com.hajunwon.devguard.data.model.SignalLayer
import com.hajunwon.devguard.ui.LocalLanguage
import com.hajunwon.devguard.ui.component.ShimmerCard
import com.hajunwon.devguard.ui.component.SignalGroupCard
import com.hajunwon.devguard.ui.theme.SecurityColors
import com.hajunwon.devguard.ui.viewmodel.SecurityViewModel

@Composable
fun DetectionLogScreen(viewModel: SecurityViewModel, onViewRawData: () -> Unit = {}) {
    val lang = LocalLanguage.current
    val isKo = lang == "ko"
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
            repeat(4) { ShimmerCard(height = 120.dp, translateX = shimmerX) }
            Spacer(Modifier.height(80.dp))
        }
        return
    }

    val triggered    = state.signals.filter { it.triggered }
    val javaCount    = triggered.count { it.layer == SignalLayer.JAVA }
    val jniCount     = triggered.count { it.layer == SignalLayer.JNI }
    val syscallCount = triggered.count { it.layer == SignalLayer.SYSCALL }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // ── Summary bar ───────────────────────────────────────────────────────
        ElevatedCard(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
            Row(
                modifier              = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment     = Alignment.CenterVertically
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text       = if (isKo) "API 레이어" else "API Layer",
                        style      = MaterialTheme.typography.labelSmall,
                        color      = SecurityColors.layerJava,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text       = if (isKo) "$javaCount 탐지" else "$javaCount triggered",
                        style      = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color      = if (javaCount > 0) SecurityColors.layerJava
                                     else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Box(
                    modifier = Modifier
                        .width(1.dp)
                        .height(40.dp)
                        .background(MaterialTheme.colorScheme.outlineVariant)
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text       = if (isKo) "JNI 레이어" else "JNI Layer",
                        style      = MaterialTheme.typography.labelSmall,
                        color      = SecurityColors.layerJni,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text       = if (isKo) "$jniCount 탐지" else "$jniCount triggered",
                        style      = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color      = if (jniCount > 0) SecurityColors.layerJni
                                     else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Box(
                    modifier = Modifier
                        .width(1.dp)
                        .height(40.dp)
                        .background(MaterialTheme.colorScheme.outlineVariant)
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text       = "Syscall",
                        style      = MaterialTheme.typography.labelSmall,
                        color      = SecurityColors.layerSyscall,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text       = if (isKo) "$syscallCount 탐지" else "$syscallCount triggered",
                        style      = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color      = if (syscallCount > 0) SecurityColors.layerSyscall
                                     else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        // ── Full signal detail per category (triggered + passed) ──────────────
        // Uses SignalGroupCard which shows triggered signals first, then expandable passed checks
        SignalCategory.entries.forEach { cat ->
            SignalGroupCard(
                category = cat,
                signals  = state.signals.filter { it.category == cat }
            )
        }

        // ── Raw Data navigation button ────────────────────────────────────────
        OutlinedButton(
            onClick  = onViewRawData,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (isKo) "Raw Data 보기" else "View Raw Data")
        }

        Spacer(Modifier.height(80.dp))
    }
}
