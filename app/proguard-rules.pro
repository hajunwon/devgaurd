# Rename source file references so stack traces don't reveal real file names
-renamesourcefileattribute SourceFile
-keepattributes LineNumberTable

# ── NativeDetector JNI bridge ────────────────────────────────────────────────
# JNI symbol lookup requires exact class + method names.
# R8 must not rename this class or its native methods.
-keep class com.hajunwon.devguard.data.detector.NativeDetector {
    native <methods>;
    public static boolean isAvailable;
}

# ── Data model / domain classes ──────────────────────────────────────────────
# Kept to avoid subtle issues with data class copy()/equals()/toString()
# across StateFlow boundaries in Compose.
-keep class com.hajunwon.devguard.data.model.** { *; }
-keep class com.hajunwon.devguard.domain.FullScanResult { *; }

# Keep enum values used in when expressions
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Keep Parcelable
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

# Keep Kotlin coroutine internals
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}

# ── Detector & domain classes ─────────────────────────────────────────────────
# Although R8 can trace most calls statically, detection logic uses reflection-
# adjacent patterns (reading system properties, file paths, package names) that
# look like dead code to the shrinker. Explicit keeps prevent silent removal.
-keep class com.hajunwon.devguard.data.detector.EmulatorDetector  { *; }
-keep class com.hajunwon.devguard.data.detector.RootDetector       { *; }
-keep class com.hajunwon.devguard.data.detector.DebugDetector      { *; }
-keep class com.hajunwon.devguard.data.detector.IntegrityDetector  { *; }
-keep class com.hajunwon.devguard.domain.SecurityAnalyzer          { *; }
