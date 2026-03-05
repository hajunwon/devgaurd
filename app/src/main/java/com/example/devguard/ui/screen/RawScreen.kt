package com.example.devguard.ui.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.devguard.ui.component.CollapsibleInfoCard
import com.example.devguard.ui.component.ShimmerCard
import com.example.devguard.ui.viewmodel.SecurityViewModel

@Composable
fun RawScreen(viewModel: SecurityViewModel) {
    val state by viewModel.uiState.collectAsState()

    if (state.isLoading) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            repeat(8) { ShimmerCard(height = 56.dp) }
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
        CollapsibleInfoCard("Emulator Signal Sources",  state.emulatorRaw)
        CollapsibleInfoCard("Root Signal Sources",      state.rootRaw)
        CollapsibleInfoCard("Debug Signal Sources",     state.debugRaw)
        CollapsibleInfoCard("Integrity Signal Sources", state.integrityRaw)
        CollapsibleInfoCard("Build Info",               state.buildInfo)
        CollapsibleInfoCard("Display Metrics",          state.displayInfo)
        CollapsibleInfoCard("Hardware & Memory",        state.hardwareInfo)
        CollapsibleInfoCard("Battery",                  state.batteryRaw)
        CollapsibleInfoCard("Sensors",                  state.sensorInfo)
        CollapsibleInfoCard("Network",                  state.networkInfo)
        CollapsibleInfoCard("Identifiers",              state.identifiers)
        CollapsibleInfoCard("System Properties",        state.props)
        CollapsibleInfoCard("/proc Info",               state.procInfo)

        Spacer(Modifier.height(80.dp))
    }
}
