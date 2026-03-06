package com.hajunwon.devguard.ui.component

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun RiskBadge(label: String, subtitle: String, score: Int, color: Color) {
    val maxScore = 20
    val animatedProgress by animateFloatAsState(
        targetValue   = (score / maxScore.toFloat()).coerceAtMost(1f),
        animationSpec = tween(800, easing = FastOutSlowInEasing),
        label         = "riskProgress"
    )
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape    = RoundedCornerShape(20.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(color.copy(alpha = 0.10f))
                .padding(28.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Box(contentAlignment = Alignment.Center) {
                CircularProgressIndicator(
                    progress    = { animatedProgress },
                    modifier    = Modifier.size(120.dp),
                    color       = color,
                    trackColor  = color.copy(alpha = 0.15f),
                    strokeWidth = 8.dp,
                    strokeCap   = StrokeCap.Round
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text       = score.toString(),
                        style      = MaterialTheme.typography.displaySmall,
                        fontWeight = FontWeight.Bold,
                        color      = color
                    )
                    Text(
                        text  = "/ $maxScore",
                        style = MaterialTheme.typography.bodySmall,
                        color = color.copy(alpha = 0.5f)
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Text(
                text       = label,
                style      = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color      = color
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text  = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = color.copy(alpha = 0.8f)
            )
        }
    }
}
