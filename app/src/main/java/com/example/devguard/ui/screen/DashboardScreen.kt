package com.example.devguard.ui.screen

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.example.devguard.data.model.SignalCategory
import com.example.devguard.ui.component.InfoCard
import com.example.devguard.ui.component.RiskBadge
import com.example.devguard.ui.component.ShimmerCard
import com.example.devguard.ui.component.SignalGroupCard
import com.example.devguard.ui.viewmodel.SecurityViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun DashboardScreen(viewModel: SecurityViewModel) {
    val state by viewModel.uiState.collectAsState()
    val dm = LocalContext.current.resources.displayMetrics

    if (state.isLoading) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            ShimmerCard(height = 200.dp)
            repeat(4) { ShimmerCard(height = 130.dp) }
            repeat(4) { ShimmerCard(height = 72.dp) }
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
        RiskBadge(
            label    = state.riskLevel.label,
            subtitle = state.riskLevel.subtitle,
            score    = state.score,
            color    = state.riskLevel.color
        )

        state.scanTime?.let { time ->
            val fmt = remember(time) {
                SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(time))
            }
            Text(
                text     = "Last scan: $fmt",
                style    = MaterialTheme.typography.bodySmall,
                color    = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.align(Alignment.CenterHorizontally)
            )
        }

        SignalCategory.entries.forEach { cat ->
            SignalGroupCard(
                category = cat,
                signals  = state.signals.filter { it.category == cat }
            )
        }

        InfoCard("Device",  "${Build.MANUFACTURER} ${Build.MODEL}\nAndroid ${Build.VERSION.RELEASE}  ·  SDK ${Build.VERSION.SDK_INT}")
        InfoCard("Display", "${dm.widthPixels} × ${dm.heightPixels}  ·  ${dm.densityDpi} DPI")
        InfoCard("CPU",     "${Runtime.getRuntime().availableProcessors()} cores  ·  ${Build.HARDWARE}")
        InfoCard("Battery", "Level: ${state.batteryPercent}%")

        Spacer(Modifier.height(80.dp))
    }
}
