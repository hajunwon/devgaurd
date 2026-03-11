package com.hajunwon.devguard.data.detector

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.hajunwon.devguard.data.model.DetectorResult
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import com.hajunwon.devguard.data.model.SignalLayer
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object IntegrityDetector {

    /**
     * TODO: Paste your production signing certificate's SHA-256 fingerprint here
     * (colon-separated uppercase hex pairs, e.g. "AB:CD:EF:...").
     * Obtain it with: keytool -printcert -jarfile your-release.apk
     * Leave empty ("") to disable this anti-repackaging check.
     */
    private const val EXPECTED_CERT_SHA256 = ""

    private val rootPackages = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.koushikdutta.rommanager",
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.devadvance.rootcloak",
        "com.devadvance.rootcloak2",
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "io.github.lsposed.manager",
        "com.saurik.substrate",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        // Magisk forks / alpha builds
        "io.github.vvb2060.magisk",
        "io.github.huskydg.magisk",    // Kitsune Mask
        // LSPatch — repackages apps with LSPosed modules inline (no Zygisk needed)
        "org.lsposed.lspatch",
        // One-click root tools (legacy, still detected for completeness)
        "com.kingroot.kinguser",
        "com.kingo.android.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
        // Anti-detection tools confirmed targeting this app (Dobby-based fgets hook)
        "com.hajunwon.devicer",
    )

    /**
     * Checks if a package is installed.
     * Key improvement: if the NameNotFoundException was thrown by an Xposed hook
     * (visible in the exception's stack trace), the package IS installed but hidden —
     * we flip the result to true.
     */
    private fun isPackageInstalled(context: Context, pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        // If Xposed threw this to hide the package, its frames appear in the stack
        e.stackTrace.any {
            it.className.contains("xposed", ignoreCase = true) ||
            it.className.contains("LSPHooker", ignoreCase = true) ||
            it.className.contains("LegacyApiSupport", ignoreCase = true)
        }
    }

    private fun getInstallerPackage(context: Context): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
            context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
        else
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(context.packageName)
    } catch (e: Exception) { null }

    private fun runGetenforce(): String = try {
        Runtime.getRuntime().exec("getenforce").inputStream.bufferedReader().readLine()?.trim() ?: "unknown"
    } catch (e: Exception) { "unavailable" }

    /**
     * Fetches signing certificate info once — reused for both debug-signing check and
     * fingerprint display to avoid a duplicate IPC call to PackageManager.
     * Returns Pair(isDebugSigned, fingerprintHex).
     */
    private fun getSigningCertInfo(context: Context): Pair<Boolean, String> = try {
        val info = context.packageManager.getPackageInfo(
            context.packageName, PackageManager.GET_SIGNING_CERTIFICATES
        )
        val cert = info.signingInfo?.apkContentsSigners?.firstOrNull()
            ?: return true to "null (no signature)"
        val x509 = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(cert.toByteArray())) as X509Certificate
        val isDebug = x509.subjectDN.name.contains("Android Debug", ignoreCase = true) ||
                      x509.issuerDN.name.contains("Android Debug", ignoreCase = true)
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.toByteArray())
            .joinToString(":") { b -> "%02X".format(b) }
        isDebug to fingerprint
    } catch (e: Exception) { false to "error: ${e.message}" }

    fun scan(context: Context): DetectorResult {
        val foundPkgs               = rootPackages.filter { isPackageInstalled(context, it) }
        val selinux                 = runGetenforce()
        val installer               = getInstallerPackage(context)
        val (debugSigned, fingerprint) = getSigningCertInfo(context)

        val rootPkgHit   = foundPkgs.isNotEmpty()
        val selinuxHit   = selinux.lowercase() == "permissive"
        val installerHit = installer != "com.android.vending" &&
                           installer != "com.google.android.feedback"
        val certMismatch = EXPECTED_CERT_SHA256.isNotEmpty() && fingerprint != EXPECTED_CERT_SHA256

        val jvmSignals = buildList {
            add(Signal(SignalCategory.INTEGRITY, "Root/hook app package detected",    "No root app packages found",   4, rootPkgHit))
            add(Signal(SignalCategory.INTEGRITY, "SELinux is Permissive (rooted)",    "SELinux is Enforcing",         3, selinuxHit, group = "int_selinux"))
            add(Signal(SignalCategory.INTEGRITY, "Not installed from Play Store",      "Installed from Play Store",    2, installerHit))
            add(Signal(SignalCategory.INTEGRITY, "APK signed with debug certificate", "APK signed with release key",  3, debugSigned))
            // Only included when EXPECTED_CERT_SHA256 is set — avoids inflating maxPossibleScore with a permanently-disabled check
            if (EXPECTED_CERT_SHA256.isNotEmpty()) {
                add(Signal(SignalCategory.INTEGRITY, "APK cert doesn't match expected release key", "APK cert matches expected key", 5, certMismatch))
            }
        }

        val jniSignals: List<Signal> = if (NativeDetector.isAvailable) listOf(
            Signal(SignalCategory.INTEGRITY, "SELinux permissive (libc)",    "SELinux enforcing", 3, NativeDetector.nativeCheckSelinuxPermissive(),   SignalLayer.JNI,     "int_selinux"),
        ) else emptyList()

        val syscallSignals: List<Signal> = if (NativeDetector.isAvailable) listOf(
            Signal(SignalCategory.INTEGRITY, "SELinux permissive (syscall)", "SELinux enforcing", 3, NativeDetector.syscallCheckSelinuxPermissive(), SignalLayer.SYSCALL, "int_selinux"),
        ) else emptyList()

        val signals = jvmSignals + jniSignals + syscallSignals

        val rawData = "=== Root/Hook App Packages ===\n" +
               (if (foundPkgs.isEmpty()) "(none detected)" else foundPkgs.joinToString("\n")) + "\n\n" +
               "=== SELinux Status ===\n$selinux\n\n" +
               "=== Installer Source ===\n${installer ?: "null (sideloaded)"}\n\n" +
               "=== APK Signature ===\nDebug-signed: $debugSigned\nSHA-256: $fingerprint"

        return DetectorResult(signals, rawData)
    }
}
