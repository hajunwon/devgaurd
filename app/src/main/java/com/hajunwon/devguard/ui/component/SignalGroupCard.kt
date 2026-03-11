package com.hajunwon.devguard.ui.component

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import com.hajunwon.devguard.data.model.SignalLayer
import com.hajunwon.devguard.ui.LocalLanguage
import com.hajunwon.devguard.ui.theme.SecurityColors

/** Small chip showing which detection layer produced this signal. */
@Composable
private fun LayerChip(layer: SignalLayer) {
    val color = SecurityColors.forLayer(layer)
    val label = when (layer) {
        SignalLayer.JAVA    -> "API"
        SignalLayer.JNI     -> "JNI"
        SignalLayer.SYSCALL -> "SYS"
    }
    Surface(
        shape  = RoundedCornerShape(3.dp),
        color  = color.copy(alpha = 0.12f),
        border = BorderStroke(0.5.dp, color.copy(alpha = 0.45f)),
    ) {
        Text(
            text     = label,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp),
            style    = MaterialTheme.typography.labelSmall,
            color    = color,
            fontSize = 9.sp,
        )
    }
}

@Composable
fun SignalGroupCard(category: SignalCategory, signals: List<Signal>) {
    val isKo       = LocalLanguage.current == "ko"
    val alertColor = SecurityColors.forCategory(category)
    val safeColor  = SecurityColors.safe
    val triggered  = signals.filter { it.triggered }
    val passed     = signals.filter { !it.triggered }
    val hasAlerts  = triggered.isNotEmpty()
    val titleColor = if (hasAlerts) alertColor else safeColor
    var showPassed by remember { mutableStateOf(false) }
    val arrowAngle by animateFloatAsState(
        targetValue = if (showPassed) 180f else 0f,
        label       = "passedArrow"
    )

    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape    = RoundedCornerShape(16.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {

            // ── Header: category name + status badge ──────────────────────────
            Row(
                modifier              = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment     = Alignment.CenterVertically,
            ) {
                Text(
                    text       = if (isKo) category.displayNameKo else category.displayName,
                    style      = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color      = titleColor,
                )
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = titleColor.copy(alpha = 0.13f),
                ) {
                    Text(
                        text       = if (hasAlerts) {
                            if (isKo) "${triggered.size}개 탐지" else "${triggered.size} triggered"
                        } else {
                            if (isKo) "✓ 이상 없음" else "✓ All clear"
                        },
                        modifier   = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        style      = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.SemiBold,
                        color      = titleColor,
                    )
                }
            }

            // ── Triggered signals ─────────────────────────────────────────────
            if (hasAlerts) {
                Spacer(Modifier.height(10.dp))
                triggered.forEach { signal ->
                    Row(
                        modifier              = Modifier.padding(vertical = 3.dp),
                        verticalAlignment     = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        LayerChip(signal.layer)
                        Text(
                            text       = "✗",
                            color      = alertColor,
                            style      = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            text  = "${signal.detectedText}  (+${signal.weight})",
                            color = alertColor,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }

            // ── Passed checks (collapsible) ───────────────────────────────────
            if (passed.isNotEmpty()) {
                if (hasAlerts) {
                    HorizontalDivider(
                        modifier  = Modifier.padding(vertical = 8.dp),
                        thickness = 0.5.dp,
                        color     = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                    )
                } else {
                    Spacer(Modifier.height(6.dp))
                }

                if (showPassed) {
                    passed.forEach { signal ->
                        Row(
                            modifier              = Modifier.padding(vertical = 3.dp),
                            verticalAlignment     = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            LayerChip(signal.layer)
                            Text(
                                text       = "✓",
                                color      = safeColor,
                                style      = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Bold,
                            )
                            Text(
                                text  = signal.passText,
                                color = safeColor,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }

                Row(
                    modifier              = Modifier
                        .fillMaxWidth()
                        .clickable { showPassed = !showPassed }
                        .padding(vertical = 6.dp),
                    verticalAlignment     = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text  = if (showPassed) {
                            if (isKo) "통과 항목 숨기기" else "Hide passed checks"
                        } else {
                            if (isKo) "${passed.size}개 항목 통과" else "${passed.size} checks passed"
                        },
                        color = safeColor.copy(alpha = 0.8f),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Icon(
                        imageVector        = Icons.Filled.KeyboardArrowDown,
                        contentDescription = if (showPassed) {
                            if (isKo) "숨기기" else "Hide"
                        } else {
                            if (isKo) "통과 항목 보기" else "Show passed checks"
                        },
                        modifier           = Modifier.size(16.dp).rotate(arrowAngle),
                        tint               = safeColor.copy(alpha = 0.8f),
                    )
                }
            }
        }
    }
}
