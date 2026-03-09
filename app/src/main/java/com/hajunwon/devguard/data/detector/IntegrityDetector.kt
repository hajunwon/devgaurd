package com.hajunwon.devguard.data.detector

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.hajunwon.devguard.data.model.DetectorResult
import com.hajunwon.devguard.data.model.Signal
import com.hajunwon.devguard.data.model.SignalCategory
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object IntegrityDetector {

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
     * Returns true if the APK is signed with a debug certificate.
     * A debug-signed APK in a production context indicates tampering or repackaging.
     */
    private fun isDebugSigned(context: Context): Boolean = try {
        val info = context.packageManager.getPackageInfo(
            context.packageName, PackageManager.GET_SIGNING_CERTIFICATES
        )
        val cert = info.signingInfo?.apkContentsSigners?.firstOrNull() ?: return true
        val x509 = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(cert.toByteArray())) as X509Certificate
        x509.subjectDN.name.contains("Android Debug", ignoreCase = true) ||
        x509.issuerDN.name.contains("Android Debug", ignoreCase = true)
    } catch (e: Exception) { false }

    /** Returns SHA-256 fingerprint of the signing certificate for display. */
    private fun getSignatureFingerprint(context: Context): String = try {
        val info = context.packageManager.getPackageInfo(
            context.packageName, PackageManager.GET_SIGNING_CERTIFICATES
        )
        val cert = info.signingInfo?.apkContentsSigners?.firstOrNull()
            ?: return "null (no signature)"
        val digest = MessageDigest.getInstance("SHA-256").digest(cert.toByteArray())
        digest.joinToString(":") { b -> "%02X".format(b) }
    } catch (e: Exception) { "error: ${e.message}" }

    fun scan(context: Context): DetectorResult {
        val foundPkgs    = rootPackages.filter { isPackageInstalled(context, it) }
        val selinux      = runGetenforce()
        val installer    = getInstallerPackage(context)
        val debugSigned  = isDebugSigned(context)
        val fingerprint  = getSignatureFingerprint(context)

        val rootPkgHit   = foundPkgs.isNotEmpty()
        val selinuxHit   = selinux.lowercase() == "permissive"
        val installerHit = installer != "com.android.vending" &&
                           installer != "com.google.android.feedback"

        val signals = listOf(
            Signal(SignalCategory.INTEGRITY, "Root/hook app package detected",  "No root app packages found",  4, rootPkgHit),
            Signal(SignalCategory.INTEGRITY, "SELinux is Permissive (rooted)",  "SELinux is Enforcing",        3, selinuxHit),
            Signal(SignalCategory.INTEGRITY, "Not installed from Play Store",    "Installed from Play Store",   2, installerHit),
            Signal(SignalCategory.INTEGRITY, "APK signed with debug certificate", "APK signed with release key", 3, debugSigned),
        )

        val rawData = "=== Root/Hook App Packages ===\n" +
               (if (foundPkgs.isEmpty()) "(none detected)" else foundPkgs.joinToString("\n")) + "\n\n" +
               "=== SELinux Status ===\n$selinux\n\n" +
               "=== Installer Source ===\n${installer ?: "null (sideloaded)"}\n\n" +
               "=== APK Signature ===\nDebug-signed: $debugSigned\nSHA-256: $fingerprint"

        return DetectorResult(signals, rawData)
    }
}
