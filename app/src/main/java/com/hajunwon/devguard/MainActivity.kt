package com.hajunwon.devguard

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.hajunwon.devguard.ui.screen.DeviceInfoScreen
import com.hajunwon.devguard.ui.theme.MyApplicationTheme
import com.hajunwon.devguard.ui.viewmodel.SecurityViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: SecurityViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
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
