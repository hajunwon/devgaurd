package com.hajunwon.devguard.ui

import android.content.Context
import androidx.compose.runtime.compositionLocalOf

/** Persists language preference ("ko" or "en") and provides a CompositionLocal. */
val LocalLanguage = compositionLocalOf { "ko" }

object LanguageManager {
    private const val PREF = "devguard_prefs"
    private const val KEY  = "language"

    fun get(context: Context): String =
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getString(KEY, "ko") ?: "ko"

    fun set(context: Context, lang: String) {
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit().putString(KEY, lang).apply()
    }
}
