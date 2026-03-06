package com.hajunwon.devguard.ui.screen

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.hajunwon.devguard.ui.viewmodel.SecurityViewModel

@Composable
fun DeviceInfoScreen(viewModel: SecurityViewModel) {
    val state by viewModel.uiState.collectAsState()
    var selectedTab by remember { mutableStateOf(0) }
    val tabs = listOf("Dashboard", "Raw Data")

    Scaffold(
        floatingActionButton = {
            FloatingActionButton(onClick = { if (!state.isLoading) viewModel.scan() }) {
                if (state.isLoading) {
                    CircularProgressIndicator(
                        modifier    = Modifier.size(24.dp),
                        strokeWidth = 2.5.dp,
                        color       = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                } else {
                    Text("↺", style = MaterialTheme.typography.titleLarge)
                }
            }
        }
    ) { _ ->
        Column {
            TabRow(selectedTabIndex = selectedTab) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = selectedTab == index,
                        onClick  = { selectedTab = index },
                        text     = { Text(title) }
                    )
                }
            }
            when (selectedTab) {
                0 -> DashboardScreen(viewModel)
                1 -> RawScreen(viewModel)
            }
        }
    }
}
