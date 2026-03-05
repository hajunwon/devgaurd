package com.example.devguard.ui.viewmodel

import android.app.Application
import androidx.compose.ui.graphics.Color
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.devguard.data.detector.SystemInfoCollector
import com.example.devguard.data.model.RiskLevel
import com.example.devguard.data.model.Signal
import com.example.devguard.domain.SecurityAnalyzer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class SecurityUiState(
    val signals: List<Signal> = emptyList(),
    val score: Int = 0,
    val riskLevel: RiskLevel = RiskLevel("...", "Scanning...", Color.Gray),
    val batteryPercent: Int = -1,
    val isLoading: Boolean = true,
    val scanTime: Long? = null,
    val props: String = "",
    val emulatorRaw: String = "",
    val rootRaw: String = "",
    val debugRaw: String = "",
    val integrityRaw: String = "",
    val buildInfo: String = "",
    val displayInfo: String = "",
    val hardwareInfo: String = "",
    val batteryRaw: String = "",
    val sensorInfo: String = "",
    val networkInfo: String = "",
    val identifiers: String = "",
    val procInfo: String = "",
)

class SecurityViewModel(application: Application) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(SecurityUiState())
    val uiState: StateFlow<SecurityUiState> = _uiState.asStateFlow()

    init { scan() }

    fun scan() {
        val context = getApplication<Application>()
        viewModelScope.launch(Dispatchers.IO) {
            _uiState.value = _uiState.value.copy(isLoading = true)

            val props = runCatching { SystemInfoCollector.systemProperties() }.getOrDefault("")
            // Single pass: each detector runs exactly once
            val scan  = runCatching { SecurityAnalyzer.fullScan(context, props) }.getOrNull()

            fun sysInfo(block: () -> String) = runCatching(block).getOrElse { "Error: ${it.message}" }

            _uiState.value = SecurityUiState(
                signals        = scan?.signals     ?: emptyList(),
                score          = scan?.score       ?: 0,
                riskLevel      = scan?.riskLevel   ?: RiskLevel("ERROR", "Scan failed", Color.Red),
                batteryPercent = runCatching { SystemInfoCollector.batteryPercent(context) }.getOrDefault(-1),
                isLoading      = false,
                scanTime       = System.currentTimeMillis(),
                props          = props,
                emulatorRaw    = scan?.emulatorRaw  ?: "Scan failed",
                rootRaw        = scan?.rootRaw      ?: "Scan failed",
                debugRaw       = scan?.debugRaw     ?: "Scan failed",
                integrityRaw   = scan?.integrityRaw ?: "Scan failed",
                buildInfo      = sysInfo { SystemInfoCollector.buildInfo() },
                displayInfo    = sysInfo { SystemInfoCollector.displayInfo(context) },
                hardwareInfo   = sysInfo { SystemInfoCollector.hardwareInfo(context) },
                batteryRaw     = sysInfo { SystemInfoCollector.batteryRaw(context) },
                sensorInfo     = sysInfo { SystemInfoCollector.sensorDetails(context) },
                networkInfo    = sysInfo { SystemInfoCollector.networkInfo(context) },
                identifiers    = sysInfo { SystemInfoCollector.identifiers(context) },
                procInfo       = sysInfo { SystemInfoCollector.procInfo() },
            )
        }
    }
}
