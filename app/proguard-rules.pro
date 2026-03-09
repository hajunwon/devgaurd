# Rename source file references so stack traces don't reveal real file names
-renamesourcefileattribute SourceFile
-keepattributes LineNumberTable

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
