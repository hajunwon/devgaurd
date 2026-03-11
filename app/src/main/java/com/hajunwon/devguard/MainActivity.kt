package com.hajunwon.devguard

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import com.hajunwon.devguard.ui.LanguageManager
import com.hajunwon.devguard.ui.LocalLanguage
import com.hajunwon.devguard.ui.screen.DeviceInfoScreen
import com.hajunwon.devguard.ui.theme.MyApplicationTheme
import com.hajunwon.devguard.ui.viewmodel.SecurityViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: SecurityViewModel by viewModels()

    private val requestPhonePermissions = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { _ -> viewModel.scan() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) { viewModel.scanIfStale() }
        })
        val missing = listOf(
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_PHONE_NUMBERS,  // required for getLine1Number() on Android 11+
        ).filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) requestPhonePermissions.launch(missing.toTypedArray())
        val lang = LanguageManager.get(this)
        setContent {
            MyApplicationTheme {
                CompositionLocalProvider(LocalLanguage provides lang) {
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = MaterialTheme.colorScheme.background
                    ) {
                        DeviceInfoScreen(viewModel)
                    }
                }
            }
        }
    }
}
