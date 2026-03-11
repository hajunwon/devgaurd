package com.hajunwon.devguard.ui.screen

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.hajunwon.devguard.ui.LocalLanguage
import com.hajunwon.devguard.ui.viewmodel.SecurityViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private data class TabItem(val title: String, val icon: ImageVector)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceInfoScreen(viewModel: SecurityViewModel) {
    val state by viewModel.uiState.collectAsState()
    val lang = LocalLanguage.current
    val isKo = lang == "ko"

    // Tab indices: 0=Dashboard, 1=Detections, 2=Settings, 3=Raw Data (hidden from TabRow)
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf(
        TabItem(if (isKo) "대시보드" else "Dashboard",  Icons.Filled.Lock),
        TabItem(if (isKo) "탐지 목록" else "Detections", Icons.Filled.Warning),
        TabItem(if (isKo) "설정"     else "Settings",    Icons.Filled.Settings),
    )

    val triggeredCount = state.signals.count { it.triggered }

    val scanTimeLabel = state.scanTime?.let { time ->
        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(time))
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        if (selectedTab == 3) {
                            // Breadcrumb back to Detections when on hidden Raw Data tab
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                TextButton(
                                    onClick  = { selectedTab = 1 },
                                    modifier = Modifier.padding(end = 4.dp),
                                ) {
                                    Text(
                                        text  = if (isKo) "← 탐지 목록" else "← Detections",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                }
                            }
                        } else {
                            Text("DevGuard", style = MaterialTheme.typography.titleLarge)
                            if (scanTimeLabel != null) {
                                Text(
                                    text  = if (isKo) "마지막 스캔: $scanTimeLabel" else "Last scan: $scanTimeLabel",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            )
        },
        floatingActionButton = {
            // Hide FAB on Raw Data tab
            if (selectedTab != 3) {
                FloatingActionButton(
                    onClick        = { if (!state.isLoading) viewModel.scan() },
                    containerColor = if (state.isLoading)
                        MaterialTheme.colorScheme.surfaceVariant
                    else
                        MaterialTheme.colorScheme.primaryContainer,
                    contentColor   = if (state.isLoading)
                        MaterialTheme.colorScheme.onSurfaceVariant
                    else
                        MaterialTheme.colorScheme.onPrimaryContainer,
                ) {
                    if (state.isLoading) {
                        CircularProgressIndicator(
                            modifier    = Modifier.size(24.dp),
                            strokeWidth = 2.5.dp,
                            color       = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        Text("↺", style = MaterialTheme.typography.titleLarge)
                    }
                }
            }
        }
    ) { innerPadding ->
        Column(modifier = Modifier.padding(innerPadding).fillMaxSize()) {
            // TabRow only shows visible tabs (not Raw Data)
            if (selectedTab != 3) {
                TabRow(selectedTabIndex = selectedTab) {
                    tabs.forEachIndexed { index, tab ->
                        Tab(
                            selected = selectedTab == index,
                            onClick  = { selectedTab = index },
                            icon     = {
                                // Show triggered-signal count badge on the Detections tab
                                if (index == 1 && triggeredCount > 0 && !state.isLoading) {
                                    BadgedBox(badge = {
                                        Badge { Text(triggeredCount.toString()) }
                                    }) {
                                        Icon(tab.icon, contentDescription = null)
                                    }
                                } else {
                                    Icon(tab.icon, contentDescription = null)
                                }
                            },
                            text = { Text(tab.title) },
                        )
                    }
                }
            }

            // Content with smooth slide + fade transition between tabs
            AnimatedContent(
                targetState   = selectedTab,
                transitionSpec = {
                    val forward = targetState > initialState
                    (slideInHorizontally(tween(280, easing = FastOutSlowInEasing)) { if (forward) it / 4 else -it / 4 } +
                        fadeIn(tween(220))) togetherWith
                        (slideOutHorizontally(tween(280, easing = FastOutSlowInEasing)) { if (forward) -it / 4 else it / 4 } +
                            fadeOut(tween(150)))
                },
                modifier = Modifier.fillMaxSize(),
                label    = "tabContent",
            ) { tab ->
                when (tab) {
                    0 -> DashboardScreen(viewModel)
                    1 -> DetectionLogScreen(viewModel, onViewRawData = { selectedTab = 3 })
                    2 -> SettingsScreen()
                    3 -> RawScreen(viewModel)
                    else -> Unit
                }
            }
        }
    }
}
