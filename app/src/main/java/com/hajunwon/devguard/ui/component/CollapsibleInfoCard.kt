package com.hajunwon.devguard.ui.component

import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp

@Composable
fun CollapsibleInfoCard(title: String, content: String) {
    var expanded by remember { mutableStateOf(false) }
    val arrowAngle by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        label = "arrow"
    )
    ElevatedCard(
        onClick = { expanded = !expanded },
        modifier = Modifier
            .fillMaxWidth()
            .animateContentSize(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
                Icon(
                    imageVector = Icons.Filled.KeyboardArrowDown,
                    contentDescription = null,
                    modifier = Modifier.rotate(arrowAngle),
                    tint = MaterialTheme.colorScheme.primary
                )
            }
            if (expanded) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Spacer(Modifier.height(8.dp))
                Text(
                    text  = buildColorizedAnnotatedString(content),
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun buildColorizedAnnotatedString(content: String) = buildAnnotatedString {
    val alertColor   = Color(0xFFEF9A9A)  // soft red for findings
    val safeColor    = Color(0xFF81C784)  // soft green for clean results
    val sectionColor = Color(0xFF90CAF9)  // soft blue for section headers

    content.lines().forEachIndexed { index, line ->
        val color = when {
            line.startsWith("===")                                  -> sectionColor
            line.contains("EXISTS",    ignoreCase = true) ||
            line.contains("DETECTED",  ignoreCase = true) ||
            line.contains(": true")                                 -> alertColor
            line.contains("not found", ignoreCase = true) ||
            line.contains(": false")   ||
            line.contains("(nothing suspicious)")                   -> safeColor
            else                                                    -> null
        }
        if (color != null) {
            withStyle(SpanStyle(color = color)) { append(line) }
        } else {
            append(line)
        }
        if (index < content.lines().lastIndex) append("\n")
    }
}
