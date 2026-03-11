package com.hajunwon.devguard.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hajunwon.devguard.data.detector.SystemInfoCollector
import com.hajunwon.devguard.data.model.RiskLevel
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.domain.SecurityAnalyzer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

data class SecurityUiState(
    val signals: List<Signal> = emptyList(),
    val score: Int = 0,
    val maxScore: Int = 0,
    val riskLevel: RiskLevel = RiskLevel("...", "Scanning...", 0xFF888888),
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

    /** Re-scans only if not already scanning and the last scan is older than [minIntervalMs] (default 60 s). */
    fun scanIfStale(minIntervalMs: Long = 60_000) {
        if (_uiState.value.isLoading) return
        val lastScan = _uiState.value.scanTime ?: 0L
        if (System.currentTimeMillis() - lastScan >= minIntervalMs) scan()
    }

    fun scan() {
        val context = getApplication<Application>()
        viewModelScope.launch(Dispatchers.IO) {
            // Full reset — clears previous results so UI shows fresh shimmer, not stale data
            _uiState.value = SecurityUiState(isLoading = true)

            fun sysInfo(block: () -> String) = runCatching(block).getOrElse { "Error: ${it.message}" }

            // Run security scan and all system info collection in parallel
            // props collection is async to avoid blocking the entire coroutine if getprop hangs
            val propsDeferred       = async { withTimeoutOrNull(3_000) { runCatching { SystemInfoCollector.systemProperties() }.getOrDefault("") } ?: "getprop timed out" }
            val batteryDeferred     = async { runCatching { SystemInfoCollector.batteryPercent(context) }.getOrDefault(-1) }
            val buildDeferred       = async { sysInfo { SystemInfoCollector.buildInfo() } }
            val displayDeferred     = async { sysInfo { SystemInfoCollector.displayInfo(context) } }
            val hardwareDeferred    = async { sysInfo { SystemInfoCollector.hardwareInfo(context) } }
            val batteryRawDeferred  = async { sysInfo { SystemInfoCollector.batteryRaw(context) } }
            val sensorDeferred      = async { sysInfo { SystemInfoCollector.sensorDetails(context) } }
            val networkDeferred     = async { sysInfo { SystemInfoCollector.networkInfo(context) } }
            val identifiersDeferred = async { sysInfo { SystemInfoCollector.identifiers(context) } }
            val procDeferred        = async { sysInfo { SystemInfoCollector.procInfo() } }

            val props = propsDeferred.await()
            val scanDeferred = async { runCatching { SecurityAnalyzer.fullScan(context, props) }.getOrNull() }

            // 15 second global timeout for the full scan
            val scan = withTimeoutOrNull(15_000) { scanDeferred.await() }

            _uiState.value = SecurityUiState(
                signals        = scan?.signals          ?: emptyList(),
                score          = scan?.score            ?: 0,
                maxScore       = scan?.maxPossibleScore ?: 0,
                riskLevel      = scan?.riskLevel        ?: RiskLevel("ERROR", "Scan failed", 0xFFFF0000),
                batteryPercent = batteryDeferred.await(),
                isLoading      = false,
                scanTime       = System.currentTimeMillis(),
                props          = props,
                emulatorRaw    = scan?.emulatorRaw  ?: "Scan failed",
                rootRaw        = scan?.rootRaw      ?: "Scan failed",
                debugRaw       = scan?.debugRaw     ?: "Scan failed",
                integrityRaw   = scan?.integrityRaw ?: "Scan failed",
                buildInfo      = buildDeferred.await(),
                displayInfo    = displayDeferred.await(),
                hardwareInfo   = hardwareDeferred.await(),
                batteryRaw     = batteryRawDeferred.await(),
                sensorInfo     = sensorDeferred.await(),
                networkInfo    = networkDeferred.await(),
                identifiers    = identifiersDeferred.await(),
                procInfo       = procDeferred.await(),
            )
        }
    }
}
