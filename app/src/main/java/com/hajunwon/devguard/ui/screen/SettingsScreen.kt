package com.hajunwon.devguard.ui.screen

import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.hajunwon.devguard.ui.LanguageManager
import com.hajunwon.devguard.ui.LocalLanguage

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val currentLang = LocalLanguage.current
    var selectedLang by remember { mutableStateOf(currentLang) }

    val isKo = selectedLang == "ko"

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // ── App info ──────────────────────────────────────────────────────────
        ElevatedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier            = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text       = "DevGuard",
                    style      = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text  = if (isKo) "Android 보안 환경 탐지 앱" else "Android Security Environment Inspector",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(6.dp))
                InfoRow(if (isKo) "버전" else "Version", "1.4.0")
                InfoRow(if (isKo) "빌드" else "Build",   "5")
                InfoRow("Min SDK", "Android 9 (API 28)")
                InfoRow("Target SDK", "Android 16 (API 36)")
            }
        }

        // ── Developer ─────────────────────────────────────────────────────────
        ElevatedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text       = if (isKo) "개발자" else "Developer",
                    style      = MaterialTheme.typography.labelSmall,
                    color      = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier   = Modifier.padding(bottom = 10.dp),
                )
                LinkRow(
                    label    = "GitHub",
                    subtitle = "github.com/hajunwon",
                    url      = "https://github.com/hajunwon",
                )
                HorizontalDivider(
                    thickness = 0.5.dp,
                    color     = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                    modifier  = Modifier.padding(vertical = 4.dp),
                )
                LinkRow(
                    label    = "Telegram",
                    subtitle = "@ow9kj1w",
                    url      = "https://t.me/ow9kj1w",
                )
            }
        }

        // ── Language ──────────────────────────────────────────────────────────
        ElevatedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier            = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text  = if (isKo) "언어 / Language" else "Language / 언어",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = selectedLang == "ko",
                        onClick  = {
                            if (selectedLang != "ko") {
                                selectedLang = "ko"
                                LanguageManager.set(context, "ko")
                                (context as? Activity)?.recreate()
                            }
                        },
                        label    = { Text("한국어") },
                        colors   = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                            selectedLabelColor     = MaterialTheme.colorScheme.onPrimaryContainer,
                        ),
                    )
                    FilterChip(
                        selected = selectedLang == "en",
                        onClick  = {
                            if (selectedLang != "en") {
                                selectedLang = "en"
                                LanguageManager.set(context, "en")
                                (context as? Activity)?.recreate()
                            }
                        },
                        label    = { Text("English") },
                        colors   = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                            selectedLabelColor     = MaterialTheme.colorScheme.onPrimaryContainer,
                        ),
                    )
                }
                Text(
                    text  = if (isKo) "언어 변경 시 앱이 재시작됩니다"
                            else      "App will restart when language is changed",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                )
            }
        }

        Spacer(Modifier.height(80.dp))
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier              = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun LinkRow(label: String, subtitle: String, url: String) {
    val context = LocalContext.current
    Row(
        modifier              = Modifier
            .fillMaxWidth()
            .clickable { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.CenterVertically,
    ) {
        Column {
            Text(label,    style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            Text(subtitle, style = MaterialTheme.typography.bodySmall,  color = MaterialTheme.colorScheme.primary)
        }
        Text("→", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
