package com.example.devguard.ui.component

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.devguard.data.model.Signal
import com.example.devguard.data.model.SignalCategory

@Composable
fun SignalGroupCard(category: SignalCategory, signals: List<Signal>) {
    val alertColor = when (category) {
        SignalCategory.EMULATOR  -> Color(0xFFEF5350)
        SignalCategory.ROOT      -> Color(0xFFFF5722)
        SignalCategory.DEBUG     -> Color(0xFFFF9800)
        SignalCategory.INTEGRITY -> Color(0xFF9C27B0)
    }
    val safeColor  = Color(0xFF4CAF50)
    val triggered  = signals.filter { it.triggered }
    val passed     = signals.filter { !it.triggered }
    val titleColor = if (triggered.isNotEmpty()) alertColor else safeColor
    var showPassed by remember { mutableStateOf(false) }

    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape    = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text       = category.displayName,
                style      = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color      = titleColor
            )
            Spacer(Modifier.height(10.dp))

            triggered.forEach { signal ->
                Row(
                    modifier              = Modifier.padding(vertical = 3.dp),
                    verticalAlignment     = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text("✗", color = alertColor, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                    Text("${signal.detectedText}  (+${signal.weight})", color = alertColor, style = MaterialTheme.typography.bodySmall)
                }
            }

            if (passed.isNotEmpty()) {
                if (showPassed) {
                    passed.forEach { signal ->
                        Row(
                            modifier              = Modifier.padding(vertical = 3.dp),
                            verticalAlignment     = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text("✓", color = safeColor, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                            Text(signal.passText, color = safeColor, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
                TextButton(
                    onClick        = { showPassed = !showPassed },
                    contentPadding = PaddingValues(horizontal = 0.dp, vertical = 4.dp)
                ) {
                    Text(
                        text  = if (showPassed) "▲  Hide passed checks" else "▼  ${passed.size} checks passed",
                        color = safeColor.copy(alpha = 0.8f),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}
