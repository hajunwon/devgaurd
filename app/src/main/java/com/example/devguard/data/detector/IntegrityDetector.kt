package com.example.devguard.data.detector

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.example.devguard.data.model.DetectorResult
import com.example.devguard.data.model.Signal
import com.example.devguard.data.model.SignalCategory

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

    private fun isPackageInstalled(context: Context, pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) { false }

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

    fun scan(context: Context): DetectorResult {
        val foundPkgs   = rootPackages.filter { isPackageInstalled(context, it) }
        val selinux     = runGetenforce()
        val installer   = getInstallerPackage(context)

        val rootPkgHit  = foundPkgs.isNotEmpty()
        val selinuxHit  = selinux.lowercase() == "permissive"
        val installerHit = installer != "com.android.vending" &&
                           installer != "com.google.android.feedback"

        val signals = listOf(
            Signal(SignalCategory.INTEGRITY, "Root/hook app package detected",  "No root app packages found",  4, rootPkgHit),
            Signal(SignalCategory.INTEGRITY, "SELinux is Permissive (rooted)",  "SELinux is Enforcing",        3, selinuxHit),
            Signal(SignalCategory.INTEGRITY, "Not installed from Play Store",    "Installed from Play Store",   2, installerHit),
        )

        val rawData = "=== Root/Hook App Packages ===\n" +
               (if (foundPkgs.isEmpty()) "(none detected)" else foundPkgs.joinToString("\n")) + "\n\n" +
               "=== SELinux Status ===\n$selinux\n\n" +
               "=== Installer Source ===\n${installer ?: "null (sideloaded)"}"

        return DetectorResult(signals, rawData)
    }
}
