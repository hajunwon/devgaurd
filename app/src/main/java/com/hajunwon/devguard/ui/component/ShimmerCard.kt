package com.hajunwon.devguard.ui.component

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * @param translateX Pass a shared animated value from the parent to synchronize
 *   shimmer phase across multiple cards. If null, creates its own animation.
 */
@Composable
fun ShimmerCard(modifier: Modifier = Modifier, height: Dp = 80.dp, translateX: Float? = null) {
    val resolvedTranslateX = if (translateX != null) {
        translateX
    } else {
        val transition = rememberInfiniteTransition(label = "shimmer")
        val x by transition.animateFloat(
            initialValue  = -600f,
            targetValue   =  600f,
            animationSpec = infiniteRepeatable(
                animation  = tween(1000, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "shimmerX"
        )
        x
    }
    val base      = MaterialTheme.colorScheme.surfaceVariant
    val highlight = MaterialTheme.colorScheme.surface
    val brush = Brush.linearGradient(
        colors = listOf(base, highlight, base),
        start  = Offset(resolvedTranslateX, 0f),
        end    = Offset(resolvedTranslateX + 600f, 0f)
    )
    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        shape    = RoundedCornerShape(16.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(height)
                .background(brush)
        )
    }
}
